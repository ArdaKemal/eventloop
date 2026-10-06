#!/usr/bin/env python3
"""Independent RFC 8441/9220 peers: hyper-h2, aioquic, and wsproto.

Run with the public websocket_routing_server example and an OpenSSL executable.
Optional dependencies stay outside the library: h2, aioquic==1.3.0, wsproto.
"""

import argparse
import asyncio
import contextlib
import socket
import ssl
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path

from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.h3.connection import H3Connection, Setting
from aioquic.h3.events import DataReceived as H3Data, HeadersReceived as H3Headers
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, StreamReset as QuicReset
from aioquic.quic.packet import QuicProtocolVersion
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, RemoteSettingsChanged, ResponseReceived, StreamEnded, StreamReset
from h2.settings import SettingCodes
from wsproto.connection import Connection, ConnectionType
from wsproto.events import BytesMessage, CloseConnection, Ping, Pong, TextMessage


class Peer:
    def __init__(self):
        self.events = defaultdict(asyncio.Queue)

    async def event(self, stream):
        kind, value = await asyncio.wait_for(self.events[stream].get(), 5)
        if kind == "failure":
            raise RuntimeError(value)
        return kind, value

    async def end(self, stream):
        # HTTP/2 reports empty DATA carrying END_STREAM before StreamEnded.
        while True:
            kind, value = await self.event(stream)
            if kind == "end":
                return
            assert kind == "data" and not value, (kind, value)

    async def get(self):
        stream = self.open()
        self.headers(stream, [(":method", "GET"), (":scheme", "https"),
                              (":authority", "localhost"), (":path", "/hello")], True)
        kind, fields = await self.event(stream)
        assert kind == "headers" and dict(fields)[":status"] == "200", (kind, fields)
        body = bytearray()
        while True:
            kind, value = await self.event(stream)
            if kind == "end":
                break
            assert kind == "data", (kind, value)
            body.extend(value)
        assert body == b"hello\n", body

    async def websocket(self):
        stream = self.open()
        self.headers(stream, [(":method", "CONNECT"), (":protocol", "websocket"),
                              (":scheme", "https"), (":authority", "localhost"),
                              (":path", "/chat"), ("sec-websocket-version", "13"),
                              ("origin", "https://localhost"),
                              ("sec-websocket-extensions", "permessage-deflate")], False)
        kind, fields = await self.event(stream)
        assert kind == "headers" and dict(fields)[":status"] == "200", (kind, fields)
        fields = dict(fields)
        assert not ({"content-length", "sec-websocket-accept", "sec-websocket-extensions"} & fields.keys())
        return stream, Connection(ConnectionType.CLIENT)


class H2Peer(Peer):
    def __init__(self, reader, writer):
        super().__init__()
        self.reader, self.writer = reader, writer
        self.http = H2Connection(H2Configuration(client_side=True, header_encoding="utf-8"))
        self.ready = asyncio.Event()
        self.window = asyncio.Event()
        self.held = {}
        self.http.initiate_connection()
        self.http.update_settings({SettingCodes.INITIAL_WINDOW_SIZE: 64})
        self.flush()
        self.receiving = asyncio.create_task(self.receive())

    def flush(self):
        self.writer.write(self.http.data_to_send())

    def open(self):
        return self.http.get_next_available_stream_id()

    def headers(self, stream, fields, end):
        self.http.send_headers(stream, fields, end_stream=end)
        self.flush()

    async def send(self, stream, data, end=False):
        while data:
            self.window.clear()
            count = min(len(data), self.http.local_flow_control_window(stream),
                        self.http.max_outbound_frame_size)
            if not count:
                await asyncio.wait_for(self.window.wait(), 5)
                continue
            self.http.send_data(stream, data[:count])
            data = data[count:]
            self.flush()
        if end:
            self.http.end_stream(stream)
            self.flush()

    def release(self, stream):
        self.http.acknowledge_received_data(self.held.pop(stream), stream)
        self.flush()

    async def receive(self):
        try:
            while data := await self.reader.read(65536):
                for event in self.http.receive_data(data):
                    stream = getattr(event, "stream_id", 0)
                    if isinstance(event, RemoteSettingsChanged):
                        enabled = event.changed_settings.get(SettingCodes.ENABLE_CONNECT_PROTOCOL)
                        if enabled and enabled.new_value == 1:
                            self.ready.set()
                    elif isinstance(event, ResponseReceived):
                        self.events[stream].put_nowait(("headers", event.headers))
                    elif isinstance(event, DataReceived):
                        self.events[stream].put_nowait(("data", event.data))
                        if stream in self.held:
                            self.held[stream] += event.flow_controlled_length
                        else:
                            self.http.acknowledge_received_data(event.flow_controlled_length, stream)
                    elif isinstance(event, StreamEnded):
                        self.events[stream].put_nowait(("end", None))
                    elif isinstance(event, StreamReset):
                        self.events[stream].put_nowait(("reset", event.error_code))
                self.window.set()
                self.flush()
        except Exception as error:
            for queue in self.events.values():
                queue.put_nowait(("failure", str(error)))
            raise

    async def close(self):
        self.receiving.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self.receiving
        self.writer.transport.abort()


class H3Peer(QuicConnectionProtocol, Peer):
    def __init__(self, *args, **kwargs):
        QuicConnectionProtocol.__init__(self, *args, **kwargs)
        Peer.__init__(self)
        self.http = H3Connection(self._quic)
        self.ready = asyncio.Event()

    def open(self):
        return self._quic.get_next_available_stream_id()

    def headers(self, stream, fields, end):
        self.http.send_headers(stream, [(k.encode(), v.encode()) for k, v in fields], end_stream=end)
        self.transmit()

    async def send(self, stream, data, end=False):
        self.http.send_data(stream, data, end_stream=end)
        self.transmit()

    def quic_event_received(self, event):
        if isinstance(event, ConnectionTerminated):
            for queue in self.events.values():
                queue.put_nowait(("failure", f"QUIC close {event.error_code}: {event.reason_phrase}"))
        elif isinstance(event, QuicReset):
            self.events[event.stream_id].put_nowait(("reset", event.error_code))
        for received in self.http.handle_event(event):
            if isinstance(received, H3Headers):
                self.events[received.stream_id].put_nowait((
                    "headers", [(k.decode(), v.decode()) for k, v in received.headers]))
            elif isinstance(received, H3Data):
                self.events[received.stream_id].put_nowait(("data", received.data))
            if received.stream_ended:
                self.events[received.stream_id].put_nowait(("end", None))
        settings = self.http.received_settings
        if settings is not None and settings.get(Setting.ENABLE_CONNECT_PROTOCOL) == 1:
            self.ready.set()


async def message(peer, stream, websocket, expected_type):
    parts = []
    while True:
        kind, data = await peer.event(stream)
        assert kind == "data", (kind, data)
        websocket.receive_data(data)
        for event in websocket.events():
            assert isinstance(event, expected_type), event
            if isinstance(event, (TextMessage, BytesMessage)):
                parts.append(event.data)
                if event.message_finished:
                    return ("" if isinstance(event, TextMessage) else b"").join(parts)
            else:
                return event


async def scenario(peer, name):
    await asyncio.wait_for(peer.ready.wait(), 5)
    first, ws = await peer.websocket()
    second, other = await peer.websocket()
    await peer.get()
    # Interleaved fragments and Ping, split across HTTP DATA boundaries.
    fragmented = ws.send(TextMessage("frag", message_finished=False))
    fragmented += ws.send(Ping(b"tick"))
    fragmented += ws.send(TextMessage("ment"))
    await peer.send(first, fragmented[:3])
    await peer.send(first, fragmented[3:])
    assert (await message(peer, first, ws, Pong)).payload == b"tick"
    assert await message(peer, first, ws, TextMessage) == "fragment"
    await peer.send(second, other.send(BytesMessage(b"healthy")))
    assert await message(peer, second, other, BytesMessage) == b"healthy"

    large = bytes(index % 251 for index in range(16384))
    if isinstance(peer, H2Peer):
        available = peer.http.remote_flow_control_window(first)
        peer.held[first] = 0
        await peer.send(first, ws.send(BytesMessage(large)))
        # The entire peer stream window is exhausted; healthy streams proceed.
        kind, data = await peer.event(first)
        assert kind == "data" and len(data) == available, (kind, len(data), available)
        ws.receive_data(data)
        partial = list(ws.events())
        assert partial and all(isinstance(event, BytesMessage) and not event.message_finished for event in partial)
        try:
            await asyncio.wait_for(peer.events[first].get(), 0.05)
        except asyncio.TimeoutError:
            pass
        else:
            raise AssertionError("server exceeded the stalled stream window")
        await peer.get()
        peer.release(first)
        rest = await message(peer, first, ws, BytesMessage)
        assert b"".join(event.data for event in partial) + rest == large
    else:
        # aioquic advertises small QUIC windows; this crosses them repeatedly.
        await peer.send(first, ws.send(BytesMessage(large)))
        assert await message(peer, first, ws, BytesMessage) == large

    # Server FIN must precede client FIN after the WebSocket Close exchange.
    await peer.send(first, ws.send(CloseConnection(1000, "done")))
    closed = await message(peer, first, ws, CloseConnection)
    assert closed.code == 1000 and closed.reason == "done", closed
    await peer.end(first)
    await peer.get()
    await peer.send(first, b"", True)
    await peer.send(second, other.send(TextMessage("still alive")))
    assert await message(peer, second, other, TextMessage) == "still alive"
    await peer.send(second, other.send(CloseConnection(1000)))
    assert isinstance(await message(peer, second, other, CloseConnection), CloseConnection)
    await peer.end(second)
    await peer.send(second, b"", True)

    bad, _ = await peer.websocket()
    await peer.send(bad, b"\x82\x01x")  # Deliberately unmasked client frame.
    while True:
        kind, value = await peer.event(bad)
        if kind == "reset":
            assert value == (8 if isinstance(peer, H2Peer) else 0x10C), value
            break
        assert kind == "data", (kind, value)
    await peer.get()
    print(f"{name}: negotiation, concurrent streams, fragmentation, Ping/Pong, flow control, Close/FIN, reset isolation passed")


async def run(port, certificate):
    context = ssl.create_default_context(cafile=str(certificate))
    context.set_alpn_protocols(["h2"])
    for attempt in range(100):
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port, ssl=context, server_hostname="localhost")
            break
        except ConnectionRefusedError:
            if attempt == 99:
                raise
            await asyncio.sleep(0.02)
    assert writer.get_extra_info("ssl_object").selected_alpn_protocol() == "h2"
    peer = H2Peer(reader, writer)
    try:
        await scenario(peer, "HTTP/2")
    finally:
        await peer.close()
    for version in (QuicProtocolVersion.VERSION_1, QuicProtocolVersion.VERSION_2):
        configuration = QuicConfiguration(is_client=True, alpn_protocols=["h3"],
            cafile=str(certificate), server_name="localhost", supported_versions=[version],
            max_stream_data=128, max_data=2048)
        async with connect("127.0.0.1", port, configuration=configuration, create_protocol=H3Peer) as peer:
            await scenario(peer, f"HTTP/3 QUIC {version.name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("server")
    parser.add_argument("openssl")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="eventloop-ws-interop-") as directory:
        root = Path(directory)
        certificate, key = root / "cert.pem", root / "key.pem"
        subprocess.run([args.openssl, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                        "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                        "-keyout", str(key), "-out", str(certificate)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            port = reserved.getsockname()[1]
        with (root / "server.log").open("w+") as log:
            server = subprocess.Popen([args.server, str(certificate), str(key), str(port)], stdout=log, stderr=log)
            try:
                asyncio.run(asyncio.wait_for(run(port, certificate), 40))
            except Exception:
                log.flush()
                log.seek(0)
                print(log.read()[-4096:])
                raise
            finally:
                server.terminate()
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()


if __name__ == "__main__":
    main()
