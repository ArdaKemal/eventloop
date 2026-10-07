#!/usr/bin/env python3
"""Exercise public HTTPS file serving with explicit HTTP/2 flow control."""

import argparse
import pathlib
import socket
import ssl
import struct
import subprocess
import tempfile
import time


def frame(kind, flags=0, stream=0, payload=b""):
    return len(payload).to_bytes(3, "big") + bytes((kind, flags)) + struct.pack("!I", stream) + payload


def literal(index, value):
    value = value.encode("ascii")
    assert index < 15 and len(value) < 127
    return bytes((index, len(value))) + value


def request(stream, path, byte_range=None, head=False):
    # Static HPACK indices: :method GET=2, HEAD literal=2, :scheme https=7,
    # :path=4, :authority=1. Literals do not modify the dynamic table.
    block = (literal(2, "HEAD") if head else b"\x82") + b"\x87"
    block += literal(4, path) + literal(1, "localhost")
    if byte_range:
        # range is static index 50 (four-bit prefix with continuation).
        value = byte_range.encode("ascii")
        block += b"\x0f\x23" + bytes((len(value),)) + value
    return frame(1, 5, stream, block)


FALLBACK_SUITE = "ECDHE-RSA-AES256-SHA384"


def client_context(fallback):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["h2"])
    if fallback:
        # CBC is unsupported by Linux kTLS, even on hosts with TLS offload.
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers(FALLBACK_SUITE)
    return context


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def system_server_accepts_fallback(openssl, root):
    """Whether a server with this host's default OpenSSL cipher settings,
    which the library leaves unchanged, negotiates the CBC suite. Some
    distribution builds (Fedora 44 with OpenSSL 3.5) leave TLS 1.2 CBC suites
    out of server defaults."""
    port = free_port()
    server = subprocess.Popen([openssl, "s_server", "-accept", str(port), "-naccept", "1", "-quiet",
                               "-cert", str(root / "cert.pem"), "-key", str(root / "key.pem")],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                connection = socket.create_connection(("127.0.0.1", port), timeout=3)
                break
            except OSError:
                time.sleep(0.02)
        else:
            raise AssertionError("openssl s_server did not start")
        context = client_context(True)
        context.set_alpn_protocols([])
        try:
            with context.wrap_socket(connection, server_hostname="localhost") as tls:
                return tls.cipher()[0] == FALLBACK_SUITE
        except ssl.SSLError:
            return False
    finally:
        server.kill()
        server.wait()


class Peer:
    def __init__(self, port, fallback):
        context = client_context(fallback)
        self.socket = context.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=3), server_hostname="localhost")
        assert self.socket.selected_alpn_protocol() == "h2"
        if fallback:
            assert self.socket.version() == "TLSv1.2"
            assert self.socket.cipher()[0] == "ECDHE-RSA-AES256-SHA384"
        self.socket.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, payload=struct.pack("!HI", 4, 1024)))

    def exact(self, size):
        result = bytearray()
        while len(result) < size:
            chunk = self.socket.recv(size - len(result))
            assert chunk, "connection closed mid-frame"
            result.extend(chunk)
        return bytes(result)

    def receive(self):
        header = self.exact(9)
        size = int.from_bytes(header[:3], "big")
        assert size <= 16384, f"oversized HTTP/2 frame: {size}"
        kind, flags = header[3:5]
        stream = int.from_bytes(header[5:], "big") & 0x7fffffff
        payload = self.exact(size)
        assert kind not in (3, 7), f"unexpected reset/GOAWAY: {kind}, {stream}, {payload.hex()}"
        if kind == 4 and not flags & 1:
            self.socket.sendall(frame(4, 1))
        return kind, flags, stream, payload

    def window(self, stream, increment):
        self.socket.sendall(frame(8, stream=stream, payload=struct.pack("!I", increment)))

    def stalled(self):
        # A timeout after complete frame consumption proves no DATA was sent
        # beyond the current stream/connection credit.
        self.socket.settimeout(0.1)
        try:
            while True:
                kind, _, _, _ = self.receive()
                assert kind != 0, "DATA arrived with exhausted flow-control credit"
        except socket.timeout:
            pass
        finally:
            self.socket.settimeout(3)

    def close(self):
        self.socket.close()


def exercise(port, payload, fallback):
    peer = Peer(port, fallback)
    try:
        expected = {1: payload, 3: payload[173:20174]}
        received = {stream: bytearray() for stream in expected}
        windows = {1: 1024, 3: 1024}
        connection_window = 65535
        headers = set()
        finished = set()
        peer.socket.sendall(request(1, "/file.bin") + request(3, "/file.bin", "bytes=173-20173"))

        def consume():
            nonlocal connection_window
            kind, flags, stream, body = peer.receive()
            if kind == 1:
                assert stream in expected and stream not in headers
                assert flags & 4, "unexpected split response headers"
                headers.add(stream)
            elif kind == 0:
                assert stream in headers and stream not in finished, "DATA outside response"
                assert not flags & 8, "unexpected padded file DATA"
                assert len(body) <= windows[stream] and len(body) <= connection_window, "flow-control overflow"
                windows[stream] -= len(body)
                connection_window -= len(body)
                received[stream].extend(body)
                assert len(received[stream]) <= len(expected[stream])
                if flags & 1:
                    assert bytes(received[stream]) == expected[stream], "file/range bytes differ"
                    finished.add(stream)
            return kind

        while any(windows.values()):
            consume()
        assert all(len(body) == 1024 for body in received.values())
        peer.stalled()
        for stream in expected:
            peer.window(stream, 200000)
            windows[stream] += 200000
        while connection_window:
            consume()
        assert sum(map(len, received.values())) == 65535
        peer.stalled()
        while finished != set(expected):
            if connection_window == 0:
                peer.window(0, 32768)
                connection_window += 32768
            consume()

        # HEAD is an empty response even for a file spanning many DATA frames.
        peer.socket.sendall(request(5, "/file.bin", head=True))
        while True:
            kind, flags, stream, body = peer.receive()
            if stream == 5:
                assert kind == 1 and flags & 1, "HEAD emitted a file body"
                break

        # Reset a response waiting for stream credit, then prove the connection
        # still accepts a new file response with intact framing and ownership.
        peer.socket.sendall(request(7, "/file.bin"))
        reset_bytes = 0
        while reset_bytes < 1024:
            kind, _, stream, body = peer.receive()
            if kind == 0 and stream == 7:
                reset_bytes += len(body)
        assert reset_bytes == 1024
        peer.socket.sendall(frame(3, stream=7, payload=struct.pack("!I", 8)) + request(9, "/tiny.bin"))
        tiny = bytearray()
        while True:
            kind, flags, stream, body = peer.receive()
            assert stream != 7, "reset response emitted further frames"
            if stream == 9 and kind == 0:
                tiny.extend(body)
                if flags & 1:
                    break
        assert bytes(tiny) == payload[:97]
        print("HTTP/2 file framing, ranges, windows, multiplexing, HEAD, reset:", "TLS 1.2 CBC fallback" if fallback else "default TLS (kTLS when available)")
    finally:
        peer.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("server")
    parser.add_argument("openssl")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="eventloop-http2-file-") as directory:
        root = pathlib.Path(directory)
        payload = bytes((index * 37 + index // 251) % 256 for index in range(180123))
        (root / "file.bin").write_bytes(payload)
        (root / "tiny.bin").write_bytes(payload[:97])
        subprocess.run([args.openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-keyout", str(root / "key.pem"), "-out", str(root / "cert.pem")], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        https_port = free_port()
        http_port = free_port()
        with (root / "server.log").open("w+") as log:
            server = subprocess.Popen([args.server, "--root", str(root), "--certificate", str(root / "cert.pem"), "--private-key", str(root / "key.pem"), "--hostname", "localhost", "--http-port", str(http_port), "--https-port", str(https_port)], stdout=log, stderr=log)
            try:
                for _ in range(100):
                    assert server.poll() is None, "server exited before readiness"
                    try:
                        with socket.create_connection(("127.0.0.1", https_port), timeout=0.1):
                            break
                    except OSError:
                        time.sleep(0.02)
                else:
                    raise AssertionError("server did not start")
                exercise(https_port, payload, False)
                if system_server_accepts_fallback(args.openssl, root):
                    exercise(https_port, payload, True)
                else:
                    print(f"skipped the userspace TLS fallback: this host's OpenSSL server "
                          f"defaults refuse {FALLBACK_SUITE}")
            except Exception:
                log.flush()
                log.seek(0)
                print(log.read())
                raise
            finally:
                server.terminate()
                try:
                    server.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()


if __name__ == "__main__":
    main()
