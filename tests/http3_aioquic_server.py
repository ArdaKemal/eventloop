"""Independent HTTP/3 fixture; invoked by run_http3_outbound.py."""

import argparse
import asyncio
import json

import aioquic
from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted
from aioquic.quic.packet import QuicProtocolVersion

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
                     verified=self.verified)
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
                     version=int(self._quic._version))
                if not valid:
                    self.close(error_code=1, reason_phrase="invalid request")
                    return
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

    server = await serve("127.0.0.1", 0, configuration=configuration,
                         create_protocol=Protocol)
    # The bound UDP socket remains owned by the fixture: no bind/free race.
    port = server._transport.get_extra_info("sockname")[1]
    emit(event="ready", port=port, version=int(version), aioquic=aioquic.__version__)
    try:
        await asyncio.Event().wait()
    finally:
        server.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", choices=["v1", "v2"], required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    asyncio.run(main(parser.parse_args()))
