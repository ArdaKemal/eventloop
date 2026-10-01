"""Independent HTTP/3 fixture; invoked by run_http3_outbound.py."""

import argparse
import asyncio
import json

import aioquic
from aioquic.buffer import Buffer
from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted
from aioquic.quic.packet import QuicPacketType, QuicProtocolVersion, pull_quic_header

LARGE_BODY = bytes(range(256)) * 128


def emit(**record):
    print(json.dumps(record), flush=True)


async def main(args):
    version = (QuicProtocolVersion.VERSION_1 if args.version == "v1"
               else QuicProtocolVersion.VERSION_2)
    configuration = QuicConfiguration(
        is_client=False, alpn_protocols=["h3"], supported_versions=[version])
    configuration.load_cert_chain(args.cert, args.key)

    class Protocol(QuicConnectionProtocol):
        def __init__(self, *positional, **keywords):
            super().__init__(*positional, **keywords)
            self.http = H3Connection(self._quic)
            self.verified = False

        def quic_event_received(self, event):
            if isinstance(event, HandshakeCompleted):
                # aioquic 1.3.0 exposes the selected version here internally.
                # Pin the dependency so a changed API fails visibly.
                actual = int(self._quic._version)
                self.verified = actual == int(version) and event.alpn_protocol == "h3"
                emit(event="handshake", version=actual, alpn=event.alpn_protocol,
                     verified=self.verified,
                     connection=id(self),
                     retry_source_cid=(self._quic._retry_source_connection_id.hex()
                                       if self._quic._retry_source_connection_id
                                       is not None else None))
                if not self.verified:
                    self.close(error_code=1, reason_phrase="wrong version or ALPN")
                    return
            for received in self.http.handle_event(event):
                if not isinstance(received, HeadersReceived):
                    continue
                headers = dict(received.headers)
                path = headers.get(b":path", b"").decode("ascii")
                authority = headers.get(b":authority", b"").decode("ascii")
                valid = (self.verified and len(headers) == len(received.headers)
                         and headers.get(b":method") == b"GET"
                         and headers.get(b":scheme") == b"https"
                         and authority == f"127.0.0.1:{port}"
                         and received.stream_ended)
                emit(event="request", path=path, authority=authority, valid=valid,
                     version=int(self._quic._version), connection=id(self),
                     stream=received.stream_id)
                if not valid:
                    self.close(error_code=1, reason_phrase="invalid request")
                    return
                if path.startswith("/multi/"):
                    _, _, size, pattern, delay = path.split("/")
                    asyncio.create_task(self.respond_multi(received.stream_id,
                        int(size), int(pattern), int(delay)))
                    continue
                if path == "/stall":
                    continue
                status = b"200"
                if path == "/large":
                    body = LARGE_BODY
                elif path in ("/empty", "/empty-content-length"):
                    status, body = b"204", b""
                elif path == "/empty-content-length-nonzero":
                    status, body = b"204", b""
                elif path == "/empty-with-body":
                    status, body = b"204", b"unexpected"
                elif path == "/missing":
                    status, body = b"404", b"missing\n"
                else:
                    body = json.dumps({"path": path, "authority": authority},
                                      sort_keys=True).encode() + b"\n"
                fields = [(b":status", status), (b"content-type", b"application/octet-stream")]
                if status != b"204" or path in (
                        "/empty-content-length", "/empty-content-length-nonzero"):
                    length = 1 if path == "/empty-content-length-nonzero" else len(body)
                    fields.append((b"content-length", str(length).encode()))
                self.http.send_headers(received.stream_id, fields)
                self.http.send_data(received.stream_id, body, end_stream=True)
                if path == "/decoder-cancel":
                    self._quic.send_stream_data(self.http._local_decoder_stream_id, b"\x40")
                elif path == "/decoder-invalid-ack":
                    self._quic.send_stream_data(self.http._local_decoder_stream_id, b"\x80")
                self.transmit()

        async def respond_multi(self, stream, size, pattern, delay):
            # Delayed headers and small independent DATA frames force requests
            # to overlap and finish in an order different from stream creation.
            await asyncio.sleep(delay / 1000)
            cancellation = (bytes([0x40 | stream]) if stream < 63
                            else bytes([0x7f, stream - 63]))
            # Split a multi-octet prefix integer across delivery boundaries.
            for byte in cancellation:
                self._quic.send_stream_data(self.http._local_decoder_stream_id, bytes([byte]))
                self.transmit()
                await asyncio.sleep(0)
            self.http.send_headers(stream, [(b":status", b"200"),
                (b"content-length", str(size).encode()),
                (b"content-type", b"application/octet-stream")])
            self.transmit()
            if not size:
                self.http.send_data(stream, b"", end_stream=True)
            for offset in range(0, size, 317):
                body = bytes(((i * 17 + pattern) & 255)
                             for i in range(offset, min(offset + 317, size)))
                self.http.send_data(stream, body, end_stream=offset + len(body) == size)
                self.transmit()
                await asyncio.sleep(0)
            self.transmit()
            emit(event="response-complete", connection=id(self), stream=stream, bytes=size)

    server = await serve("127.0.0.1", 0, configuration=configuration,
                         create_protocol=Protocol, retry=args.retry)

    class ObservedTransport:
        """Record actual Retry sends while keeping aioquic's token handling intact."""

        def __init__(self, transport):
            self.transport = transport

        def __getattr__(self, name):
            return getattr(self.transport, name)

        def sendto(self, data, addr=None):
            header = pull_quic_header(Buffer(data=data),
                                      host_cid_length=configuration.connection_id_length)
            self.transport.sendto(data, addr)
            if header.packet_type == QuicPacketType.RETRY:
                emit(event="retry", version=int(header.version),
                     source_cid=header.source_cid.hex(), token_bytes=len(header.token))

    # The pinned server sends Retry through this transport before creating a
    # connection. A matching handshake CID proves the token-bearing restart
    # was accepted, rather than merely observing a tokenless Initial.
    server._transport = ObservedTransport(server._transport)
    # The bound UDP socket remains owned by the fixture: no bind/free race.
    port = server._transport.get_extra_info("sockname")[1]
    emit(event="ready", port=port, version=int(version), aioquic=aioquic.__version__,
         retry=args.retry)
    try:
        await asyncio.Event().wait()
    finally:
        server.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", choices=["v1", "v2"], required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--retry", action="store_true",
                        help="require address validation with a Retry packet")
    asyncio.run(main(parser.parse_args()))
