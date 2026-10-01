"""Interop check for the C++ echo example using Python's websockets library.

Run with: python3 tests/run_websocket_server.py build/websocket_echo_server
"""

import asyncio
import socket
import subprocess
import sys
import time

import websockets


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


async def exercise(url, number):
    async with websockets.connect(url, open_timeout=3, close_timeout=3) as client:
        text = f"hello, WebSocket {number} 🌍"
        await client.send(text)
        assert await client.recv() == text

        payload = bytes(range(256)) * 32
        await client.send(payload)
        assert await client.recv() == payload

        await client.send(["fragmented ", "text ", "message"])
        assert await client.recv() == "fragmented text message"

        pong = await client.ping(b"interop")
        await asyncio.wait_for(pong, 3)
        await client.close(code=1000, reason="done")
        assert client.close_code == 1000


async def main(binary):
    port = free_port()
    server = subprocess.Popen(
        [binary, str(port)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
    )
    try:
        deadline = time.monotonic() + 5
        while True:
            if server.poll() is not None:
                raise RuntimeError(f"server exited early: {server.stderr.read().decode()}")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("server did not start")
                await asyncio.sleep(0.05)

        url = f"ws://127.0.0.1:{port}/"
        await asyncio.wait_for(asyncio.gather(*(exercise(url, n) for n in range(3))), 10)
        print("WebSocket server interop passed: concurrent text, binary, fragments, ping, close")
    except Exception:
        server.terminate()
        server.wait(timeout=3)
        print(server.stderr.read().decode(), file=sys.stderr)
        raise
    finally:
        server.terminate()
        try:
            server.wait(timeout=3)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=3)
        server.stderr.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: run_websocket_server.py /path/to/websocket_echo_server")
    asyncio.run(main(sys.argv[1]))
