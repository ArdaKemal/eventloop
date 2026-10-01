"""Tiny HTTP/1.1 and TLS HTTP/2 fixtures for the Wayfarer W4 checks.

Only the surface Wayfarer needs is implemented: a per-target 200 body with a
Content-Length, HEAD without a body, and a /stall target that never answers so
the client deadline and output-preservation paths can be exercised.

Invoked by run_w4.py; emits one JSON object per line on stdout.
"""

import argparse
import json
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import h2.config
import h2.connection
import h2.events


def emit(**record):
    print(json.dumps(record), flush=True)


def body_for(target):
    return b"w4 " + target.encode("latin-1", "replace")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def respond(self, head):
        raw = self.path
        path = urlsplit(raw).path
        emit(event="request", mode="h1", method=self.command, path=path, target=raw)
        if path == "/stall":
            time.sleep(30)
            return
        body = body_for(raw)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def do_GET(self):
        self.respond(False)

    def do_HEAD(self):
        self.respond(True)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length:
            self.rfile.read(length)
        self.respond(False)


def serve_h1(port):
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    return server, server.server_address[1]


class H2Handler:
    def __init__(self, tls):
        self.tls = tls
        self.conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False, header_encoding=None))
        self.conn.initiate_connection()
        tls.sendall(self.conn.data_to_send())

    def run(self):
        try:
            while True:
                data = self.tls.recv(65535)
                if not data:
                    break
                events = self.conn.receive_data(data)
                for event in events:
                    if isinstance(event, h2.events.RequestReceived):
                        headers = dict(event.headers)
                        method = headers.get(b":method", b"")
                        target = headers.get(b":path", b"").decode("latin-1", "replace")
                        path = urlsplit(target).path
                        emit(event="request", mode="h2",
                             method=method.decode("latin-1", "replace"),
                             path=path, target=target)
                        if path == "/stall":
                            continue
                        body = body_for(target)
                        self.conn.send_headers(event.stream_id, [
                            (b":status", b"200"),
                            (b"content-type", b"text/plain"),
                            (b"content-length", str(len(body)).encode())],
                            end_stream=(method == b"HEAD"))
                        if method != b"HEAD":
                            self.conn.send_data(event.stream_id, body, end_stream=True)
                    elif isinstance(event, h2.events.DataReceived):
                        self.conn.acknowledge_received_data(
                            event.flow_controlled_length, event.stream_id)
                out = self.conn.data_to_send()
                if out:
                    self.tls.sendall(out)
        except (OSError, ssl.SSLError):
            pass
        finally:
            try:
                self.tls.close()
            except OSError:
                pass


def serve_h2(port, cert, key):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    context.set_alpn_protocols(["h2"])
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(16)

    def accept_loop():
        while True:
            try:
                connection, _ = listener.accept()
            except OSError:
                break
            try:
                tls = context.wrap_socket(connection, server_side=True)
            except (OSError, ssl.SSLError):
                connection.close()
                continue
            if tls.selected_alpn_protocol() != "h2":
                tls.close()
                continue
            threading.Thread(target=H2Handler(tls).run, daemon=True).start()

    threading.Thread(target=accept_loop, daemon=True).start()
    return listener, listener.getsockname()[1]


def main(args):
    if args.mode == "h1":
        server, port = serve_h1(args.port)
        emit(event="ready", port=port, mode="h1")
        server.serve_forever()
    else:
        _, port = serve_h2(args.port, args.cert, args.key)
        emit(event="ready", port=port, mode="h2")
        threading.Event().wait()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["h1", "h2"], required=True)
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--cert")
    parser.add_argument("--key")
    main(parser.parse_args())
