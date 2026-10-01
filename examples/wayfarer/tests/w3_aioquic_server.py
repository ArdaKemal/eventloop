"""Controlled HTTP/3 fixture for the Wayfarer W3 acceptance checks.

Each request path selects a response shape. Normal responses go through
aioquic's H3Connection (static QPACK, because the client advertises a zero
dynamic table). Malformed, unsupported, oversized and trailer cases bypass the
H3Connection and write raw request-stream bytes so the client's bounded parser
sees exact wire input.

Invoked by run_w3_aioquic.py; emits one JSON object per line on stdout.
"""

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

BINARY_BODY = bytes(range(256)) * 512          # 128 KiB, not text-safe
LARGE_BODY = bytes((i * 7 + 3) & 0xFF for i in range(200_000))


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
                actual = int(self._quic._version)
                self.verified = actual == int(version) and event.alpn_protocol == "h3"
                emit(event="handshake", version=actual, alpn=event.alpn_protocol,
                     verified=self.verified)
                if not self.verified:
                    self.close(error_code=1, reason_phrase="wrong version or ALPN")
                    return
            for received in self.http.handle_event(event):
                if isinstance(received, HeadersReceived):
                    self.dispatch(received)

        def raw(self, stream, data, end_stream=True):
            self._quic.send_stream_data(stream, data, end_stream=end_stream)
            self.transmit()

        def port(self):
            return self._transport.get_extra_info("sockname")[1]

        def dispatch(self, received):
            headers = dict(received.headers)
            method = headers.get(b":method", b"").decode("ascii", "replace")
            path = headers.get(b":path", b"").decode("ascii", "replace")
            emit(event="request", path=path, method=method,
                 version=int(self._quic._version), verified=self.verified)
            if not self.verified:
                return
            stream = received.stream_id
            origin = f"https://127.0.0.1:{self.port()}"

            if path == "/stall":
                return
            if path == "/truncated":
                self.http.send_headers(stream, [
                    (b":status", b"200"),
                    (b"content-length", b"10"),
                    (b"content-type", b"text/plain")])
                self.http.send_data(stream, b"1234", end_stream=True)
                self.transmit()
                return
            if path == "/overlength":
                self.http.send_headers(stream, [
                    (b":status", b"200"),
                    (b"content-length", b"2"),
                    (b"content-type", b"text/plain")])
                self.http.send_data(stream, b"abcd", end_stream=True)
                self.transmit()
                return
            if path == "/trailers":
                self.http.send_headers(stream, [
                    (b":status", b"200"),
                    (b"content-length", b"4"),
                    (b"content-type", b"text/plain")])
                self.http.send_data(stream, b"body", end_stream=False)
                self.http.send_headers(stream, [(b"x-trailer", b"value")],
                                       end_stream=True)
                self.transmit()
                return
            if path == "/split":
                self.http.send_headers(stream, [
                    (b":status", b"200"),
                    (b"content-length", b"6"),
                    (b"content-type", b"text/plain")])
                self.http.send_data(stream, b"ab", end_stream=False)
                self.transmit()
                self.http.send_data(stream, b"cd", end_stream=False)
                self.transmit()
                self.http.send_data(stream, b"ef", end_stream=True)
                self.transmit()
                return
            if path == "/badqp":
                # Static-QPACK prefix, then an indexed field line with T=0
                # (dynamic table) which this client must reject.
                self.raw(stream, b"\x01\x03\x00\x00\x80")
                return
            if path == "/badqp-postbase":
                # Indexed field line with a post-base index (0001xxxx).
                self.raw(stream, b"\x01\x03\x00\x00\x10")
                return
            if path == "/badqp-dynamic-name":
                # Literal field line with a dynamic name reference (01 0 0 ...).
                self.raw(stream, b"\x01\x03\x00\x00\x40")
                return
            if path == "/oversized-headers":
                self.raw(stream, b"\x01\x80\x01\x00\x01")
                return
            if path == "/oversized-data":
                self.http.send_headers(stream, [(b":status", b"200")])
                self.transmit()
                self.raw(stream, b"\x00\x80\x01\x00\x01")
                return
            if path == "/malformed":
                # HEADERS claims 5 payload bytes but only 3 arrive, then FIN.
                self.raw(stream, b"\x01\x05\x00\x00")
                return
            if path == "/binary":
                self.respond(stream, method, b"200", BINARY_BODY)
                return
            if path == "/large":
                self.respond(stream, method, b"200", LARGE_BODY)
                return
            if path == "/huge":
                self.respond(stream, method, b"200", b"x" * (16 * 1024 * 1024 + 1))
                return
            if path == "/manyfields-ok":
                fields = [(b":status", b"200")] + [
                    (f"x-f{i}".encode(), b"v") for i in range(126)]
                fields.append((b"content-length", b"7"))
                self.http.send_headers(stream, fields)
                self.http.send_data(stream, b"many-ok", end_stream=True)
                self.transmit()
                return
            if path == "/manyfields":
                fields = [(b":status", b"200")] + [
                    (f"x-f{i}".encode(), b"v") for i in range(127)]
                fields.append((b"content-length", b"7"))
                self.http.send_headers(stream, fields)
                self.http.send_data(stream, b"many-ok", end_stream=True)
                self.transmit()
                return
            if path == "/status/304-with-length":
                # A 304 may describe the representation's length without a body.
                self.http.send_headers(stream, [
                    (b":status", b"304"),
                    (b"content-length", b"12345")], end_stream=True)
                self.transmit()
                return
            if path.startswith("/status/"):
                code = path.rsplit("/", 1)[1].encode()
                body = b"" if code in (b"204", b"304") else b"status-body"
                self.respond(stream, method, code, body)
                return
            if path == "/redir/nolocation":
                self.respond(stream, method, b"302", b"")
                return
            if path == "/redir/to404":
                self.respond(stream, method, b"302", b"", extra=[
                    (b"location", b"/status/404")])
                return
            if path == "/redir/loop":
                self.respond(stream, method, b"302", b"", extra=[
                    (b"location", b"/redir/loop")])
                return
            if path == "/redir/downgrade":
                self.respond(stream, method, b"302", b"", extra=[
                    (b"location", f"http://127.0.0.1:{self.port()}/ok".encode())])
                return
            if path == "/redir/rel":
                self.respond(stream, method, b"302", b"", extra=[
                    (b"location", b"/ok")])
                return
            if path == "/redir/abs":
                self.respond(stream, method, b"302", b"", extra=[
                    (b"location", f"{origin}/ok".encode())])
                return
            if path == "/redir/proto":
                self.respond(stream, method, b"302", b"", extra=[
                    (b"location", f"//127.0.0.1:{self.port()}/ok".encode())])
                return
            if path.startswith("/hop/"):
                depth = int(path.rsplit("/", 1)[1])
                if depth >= 11:
                    self.respond(stream, method, b"200", b"deep")
                else:
                    self.respond(stream, method, b"302", b"", extra=[
                        (b"location", f"/hop/{depth + 1}".encode())])
                return
            if path == "/ok":
                self.respond(stream, method, b"200", b"ok-body")
                return
            self.respond(stream, method, b"200", f"path={path}".encode())

        def respond(self, stream, method, status, body, extra=None):
            fields = [(b":status", status)]
            if extra:
                fields.extend(extra)
            if status not in (b"204", b"304"):
                fields.append((b"content-type", b"text/plain"))
                fields.append((b"content-length", str(len(body)).encode()))
            self.http.send_headers(stream, fields,
                                   end_stream=(method == "HEAD" or not body))
            self.transmit()
            if method != "HEAD" and body:
                # Deliberately chunk larger bodies into several DATA frames.
                for offset in range(0, len(body), 30000):
                    chunk = body[offset:offset + 30000]
                    self.http.send_data(stream, chunk,
                                        end_stream=offset + len(chunk) == len(body))
                    self.transmit()

    server = await serve("127.0.0.1", 0, configuration=configuration,
                         create_protocol=Protocol, retry=False)
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
