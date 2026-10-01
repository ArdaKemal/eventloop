# Outbound WebSocket echo client

Build with CMake and run one echo exchange:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target websocket_client
./build/websocket_client wss://echo.websocket.org/ "hello"
```

The client accepts `ws://` and `wss://` URLs, resolves numeric IPv4/IPv6 or DNS names on the bounded worker, verifies system-trusted TLS certificates and hostnames, validates the HTTP upgrade, sends a masked text frame, and checks one echoed text message. It skips up to 16 preceding control or greeting frames. It limits messages to 4096 bytes and does not support fragmented messages, redirects, proxies, or a reusable client API.

Probe five distinct public URLs, or pass your own URL list:

```sh
python3 examples/probe_websocket_client.py --client ./build/websocket_client
python3 examples/probe_websocket_client.py --client ./build/websocket_client \
  wss://echo.websocket.org/ wss://your-echo.example/path
```

The default list is in the probe script. Public echo services can change or disappear; the script reports each URL and exits nonzero if any probe fails. A working DNS resolver and direct outbound TCP/TLS access are required. The probe checks that each server echoes the exact message sent.

The local handshake regression accepts lowercase HTTP field names and a mixed-case `Upgrade` token, and sends a greeting before the echo:

```sh
python3 examples/test_websocket_client_headers.py --client ./build/websocket_client
```
