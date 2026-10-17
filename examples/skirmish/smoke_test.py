#!/usr/bin/env python3
"""Bounded draft-07 wire smoke test against the actual Skirmish executable."""

import argparse
import asyncio
import base64
from collections import deque
import hashlib
import http.client
import json
from pathlib import Path
import signal
import socket
import ssl
import struct
import subprocess
import tempfile
import time

import aioquic
from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.buffer import Buffer
from aioquic.h3.connection import H3Connection, Setting
from aioquic.h3.events import DataReceived, DatagramReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, StreamDataReceived, StreamReset
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec


class Peer(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # aioquic 1.3.0 advertises draft-07 MAX_SESSIONS=1, H3_DATAGRAM=1,
        # and no draft-16 WT_ENABLED or RESET_STREAM_AT extension.
        self.http = H3Connection(self._quic, enable_webtransport=True)
        self.changed = asyncio.Event()
        self.failure = None
        self.headers = {}
        self.buffers = {}
        self.ended = set()
        self.wt_streams = set()
        self.datagrams = deque()
        self.session = None
        self.closing = False

    def received(self, stream, data, ended):
        assert stream in self.buffers, f"unexpected stream {stream}"
        buffer = self.buffers[stream]
        assert len(buffer) + len(data) <= 8192, f"stream {stream} exceeds smoke-test bound"
        buffer.extend(data)
        if ended:
            self.ended.add(stream)

    def quic_event_received(self, event):
        try:
            if isinstance(event, ConnectionTerminated):
                raise RuntimeError(f"QUIC close {event.error_code}: {event.reason_phrase}")
            if isinstance(event, StreamReset):
                # Ending a session resets its remaining WT streams with
                # WT_SESSION_GONE; the CONNECT close capsule is checked below.
                if not (self.closing and event.stream_id in self.wt_streams
                        and event.error_code == 0x170D7B68):
                    raise RuntimeError(f"stream {event.stream_id} reset: {event.error_code}")
            if isinstance(event, StreamDataReceived) and event.stream_id in self.wt_streams:
                # The response direction of a client bidi WT stream has no
                # HTTP/3 framing or second WT header. Read its QUIC bytes directly.
                self.received(event.stream_id, event.data, event.end_stream)
            else:
                for received in self.http.handle_event(event):
                    if isinstance(received, HeadersReceived):
                        assert received.stream_id in self.buffers
                        assert received.stream_id not in self.headers, "unexpected trailing HEADERS"
                        self.headers[received.stream_id] = dict(received.headers)
                        self.received(received.stream_id, b"", received.stream_ended)
                    elif isinstance(received, DataReceived):
                        self.received(received.stream_id, received.data, received.stream_ended)
                    elif isinstance(received, DatagramReceived):
                        assert received.stream_id == self.session, "wrong datagram session"
                        assert len(received.data) <= 1200, "oversized datagram"
                        assert len(self.datagrams) < 64, "datagram receive queue full"
                        self.datagrams.append(received.data)
                    else:
                        raise RuntimeError(f"unexpected HTTP/3 event: {received}")
        except Exception as error:
            self.failure = error
        self.changed.set()

    async def wait(self, predicate, label):
        try:
            async with asyncio.timeout(5):
                while True:
                    self.changed.clear()
                    if self.failure:
                        raise self.failure
                    result = predicate()
                    if result is not None:
                        return result
                    await self.changed.wait()
        except TimeoutError as error:
            raise TimeoutError(f"waiting for {label}") from error

    async def request(self, authority, origin):
        await self.wait(lambda: self.http.received_settings, "server SETTINGS")
        settings = self.http.received_settings
        for setting in (Setting.ENABLE_CONNECT_PROTOCOL, Setting.H3_DATAGRAM,
                        Setting.ENABLE_WEBTRANSPORT):
            assert settings.get(setting) == 1, f"missing server setting {setting}"
        self.session = self._quic.get_next_available_stream_id()
        self.buffers[self.session] = bytearray()
        fields = [(b":method", b"CONNECT"), (b":protocol", b"webtransport"),
                  (b":scheme", b"https"), (b":authority", authority.encode()),
                  (b":path", b"/arena"), (b"wt-available-protocols", b'"skirmish/1"')]
        if origin is not None:
            fields.append((b"origin", origin.encode()))
        self.http.send_headers(self.session, fields)
        self.transmit()
        return await self.wait(lambda: self.headers.get(self.session), "CONNECT response")

    def stream(self, unidirectional=False):
        stream = self.http.create_webtransport_stream(self.session, unidirectional)
        self.wt_streams.add(stream)
        self.buffers[stream] = bytearray()
        return stream

    def send(self, stream, data, fin=False):
        self._quic.send_stream_data(stream, data, end_stream=fin)
        self.transmit()

    async def exact(self, stream, size):
        def take():
            buffer = self.buffers[stream]
            if len(buffer) >= size:
                result = bytes(buffer[:size])
                del buffer[:size]
                return result
            assert stream not in self.ended, f"early FIN on stream {stream}"
        return await self.wait(take, f"{size} bytes on stream {stream}")

    async def message(self, stream):
        size, = struct.unpack("<H", await self.exact(stream, 2))
        assert 1 <= size <= 8192, f"invalid control message length {size}"
        return await self.exact(stream, size)

    async def until_fin(self, stream):
        return await self.wait(
            lambda: bytes(self.buffers[stream]) if stream in self.ended else None,
            f"FIN on stream {stream}")

    def datagram(self, data):
        self.http.send_datagram(self.session, data)
        self.transmit()

    async def next_datagram(self):
        return await self.wait(lambda: self.datagrams.popleft() if self.datagrams else None,
                               "datagram")


def bootstrap(port, server):
    # The page first accepts the self-signed HTTPS certificate and fetches its
    # hash. Compare that hash with the certificate, then trust this exact cert
    # for QUIC rather than disabling QUIC certificate verification.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    deadline = time.monotonic() + 5
    while True:
        assert server.poll() is None, f"server exited with {server.returncode}"
        connection = http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=1)
        try:
            connection.connect()
            certificate = connection.sock.getpeercert(binary_form=True)
            connection.request("GET", "/cert-hash")
            response = connection.getresponse()
            body = response.read(4097)
            assert response.status == 200 and len(body) <= 4096, "bad /cert-hash response"
            assert response.getheader("cache-control") == "no-store"
            digest = base64.b64decode(json.loads(body)["sha256"], validate=True)
            assert digest == hashlib.sha256(certificate).digest(), "certificate hash mismatch"
            cert = x509.load_der_x509_certificate(certificate)
            key = cert.public_key()
            assert isinstance(key, ec.EllipticCurvePublicKey) and key.curve.name == "secp256r1"
            assert (cert.not_valid_after_utc - cert.not_valid_before_utc).total_seconds() <= 14 * 86400
            return ssl.DER_cert_to_PEM_cert(certificate).encode()
        except ConnectionRefusedError:
            if time.monotonic() >= deadline:
                raise TimeoutError("waiting for HTTPS startup")
            time.sleep(0.02)
        finally:
            connection.close()


async def scenario(port, certificate):
    authority = f"127.0.0.1:{port}"
    origin = f"https://{authority}"
    configuration = QuicConfiguration(is_client=True, alpn_protocols=["h3"],
        cadata=certificate, server_name="127.0.0.1", max_datagram_frame_size=1232,
        max_data=65536, max_stream_data=16384, idle_timeout=5)
    for rejected_origin in (None, "https://foreign.invalid"):
        async with connect("127.0.0.1", port, configuration=configuration, create_protocol=Peer) as peer:
            head = await peer.request(authority, rejected_origin)
            assert head[b":status"] == b"403", f"origin accepted: {rejected_origin}"
            assert await peer.until_fin(peer.session) == b"", "rejection body"

    async with connect("127.0.0.1", port, configuration=configuration, create_protocol=Peer) as peer:
        head = await peer.request(authority, origin)
        assert head[b":status"] == b"200", head
        assert head.get(b"wt-protocol") == b'"skirmish/1"', head
        assert peer.session not in peer.ended, "CONNECT ended before session traffic"

        name = b"smoke"
        control = peer.stream()
        hello = bytes((1, len(name))) + name
        framed = struct.pack("<H", len(hello)) + hello
        # Fragment both the length prefix and HELLO payload across writes.
        for part in (framed[:1], framed[1:4], framed[4:]):
            peer.send(control, part)
            await asyncio.sleep(0.01)
        welcome = await peer.message(control)
        kind, player, tick_rate, snapshot_rate, width, height = struct.unpack_from("<BBHHBB", welcome)
        assert (kind, player, tick_rate, snapshot_rate) == (1, 0, 60, 30), welcome[:8]
        assert width > 0 and height > 0 and len(welcome) == 9 + width * height
        assert set(welcome[8:-1]) <= {0, 1, 2, 3, 4} and welcome[-1] == 0, "map/initial roster"
        assert await peer.message(control) == bytes((2, player, len(name))) + name, "JOIN"

        ping = struct.pack("<Bd", 2, 1234.5)
        # One idle input, seq=1. Snapshot ack must prove it reached the simulation.
        input_packet = struct.pack("<BIBBHI", 1, 1, 1, 0, 0, 0)
        pong = ack = False
        next_retry = 0
        async with asyncio.timeout(5):
            while not (pong and ack):
                # DATAGRAMs are unreliable: retry identical input (deduplicated
                # by the server) and ping at most ten times per second.
                now = asyncio.get_running_loop().time()
                if now >= next_retry:
                    peer.datagram(ping)
                    peer.datagram(input_packet)
                    next_retry = now + 0.1
                data = await peer.next_datagram()
                if data[:1] == b"\x02":
                    assert data == ping, "PONG differs from PING"
                    pong = True
                else:
                    assert len(data) == 43 and data[0] == 3, "single-player snapshot layout"
                    tick, seq, x, y, hp, flags = struct.unpack_from("<IIddBB", data, 1)
                    assert tick > 0 and seq in (0, 1)
                    assert 0 < x < width and 0 < y < height and (hp, flags) == (100, 1)
                    assert data[31:33] == bytes((1, player)) and data[-2:] == b"\0\0", "snapshot roster"
                    ack |= seq == 1

        chat = b"smoke chat"
        peer.send(peer.stream(unidirectional=True), chat, fin=True)
        assert await peer.message(control) == bytes((5, player, len(chat))) + chat, "CHAT broadcast"
        scoreboard = peer.stream()
        peer.send(scoreboard, b"\x01", fin=True)
        expected = bytes((1, player, len(name))) + name + b"\0\0\0\0"
        assert await peer.until_fin(scoreboard) == expected, "scoreboard payload/FIN"

        # Control FIN means leaving; require a clean CLOSE_SESSION and CONNECT FIN.
        peer.closing = True
        peer.send(control, b"", fin=True)
        closed = Buffer(data=await peer.until_fin(peer.session))
        assert closed.pull_uint_var() == 0x2843 and closed.pull_uint_var() == 4
        assert closed.pull_uint32() == 0 and closed.eof(), "session close code/reason"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    args = parser.parse_args()
    if aioquic.__version__ != "1.3.0":
        raise RuntimeError("install aioquic==1.3.0 for this smoke test")
    # Reserve an ephemeral port available to both TCP and UDP. The child binds
    # it after release, as in the other subprocess integration tests.
    with socket.socket() as tcp, socket.socket(type=socket.SOCK_DGRAM) as udp:
        tcp.bind(("127.0.0.1", 0))
        port = tcp.getsockname()[1]
        udp.bind(("127.0.0.1", port))
    with tempfile.TemporaryDirectory(prefix="eventloop-skirmish-smoke-") as temporary:
        with (Path(temporary) / "server.log").open("w+") as log:
            server = subprocess.Popen([str(args.server.resolve()), "--bind", "127.0.0.1",
                "--port", str(port), "--max-players", "1",
                "--web", str(Path(__file__).resolve().parent / "web")], stdout=log, stderr=log)
            try:
                try:
                    certificate = bootstrap(port, server)
                    asyncio.run(asyncio.wait_for(scenario(port, certificate), 20))
                finally:
                    if server.poll() is None:
                        server.send_signal(signal.SIGINT)
                    try:
                        server.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        server.wait(timeout=3)
                assert server.returncode == 0, f"server shutdown failed: {server.returncode}"
            except Exception:
                log.seek(0)
                print(log.read()[-4096:])
                raise
    print("Skirmish draft-07: certificate, Origin, skirmish/1, HELLO/WELCOME, "
          "ping/pong, input/snapshot ack, chat, scoreboard/FIN, close passed")


if __name__ == "__main__":
    main()
