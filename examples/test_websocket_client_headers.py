#!/usr/bin/env python3
"""Check the client accepts lowercase HTTP upgrade fields and token case."""

import argparse
import base64
import hashlib
import socket
import subprocess
import threading

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def serve(listener, errors):
    try:
        with listener.accept()[0] as connection:
            connection.settimeout(5)
            request = b""
            while b"\r\n\r\n" not in request:
                request += connection.recv(4096)
            key = next(line.split(b":", 1)[1].strip() for line in request.split(b"\r\n")
                       if line.lower().startswith(b"sec-websocket-key:"))
            accept = base64.b64encode(hashlib.sha1(key + GUID.encode()).digest())
            connection.sendall(b"HTTP/1.1 101 Switching Protocols\r\n"
                               b"upgrade: WEBSOCKET\r\nconnection: Upgrade\r\n"
                               b"sec-websocket-accept: " + accept + b"\r\n\r\n")
            header = connection.recv(2)
            if len(header) != 2 or header[0] != 0x81 or header[1] != 0x80 | 11:
                raise AssertionError(f"unexpected client frame: {header!r}")
            body = b""
            while len(body) < 15:
                body += connection.recv(15 - len(body))
            mask, masked = body[:4], body[4:]
            payload = bytes(value ^ mask[index % 4] for index, value in enumerate(masked))
            if payload != b"header-case":
                raise AssertionError(f"unexpected payload: {payload!r}")
            connection.sendall(b"\x81\x08greeting")
            connection.sendall(b"\x81\x0b" + payload)
    except Exception as error:
        errors.append(error)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", default="./build/websocket_client")
    args = parser.parse_args()
    errors = []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        thread = threading.Thread(target=serve, args=(listener, errors), daemon=True)
        thread.start()
        result = subprocess.run([args.client, f"ws://127.0.0.1:{listener.getsockname()[1]}/",
                                 "header-case"], capture_output=True, text=True, timeout=7)
        thread.join(5)
    if errors or result.returncode or result.stdout.strip() != "echo: header-case":
        raise AssertionError(f"server={errors!r}, client={result!r}")
    print("lowercase upgrade headers accepted")


if __name__ == "__main__":
    main()
