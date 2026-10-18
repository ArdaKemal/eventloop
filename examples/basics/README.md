# Basic examples

Single-file programs that each show one public API. The root CMake build
produces them in the build directory; `--help` prints each one's usage.

| Program | Shows | Usage |
| --- | --- | --- |
| [tcp_echo](tcp_echo.cc) | TCP accept, owned streams, partial I/O | `tcp_echo [port]` (7000) |
| [tls_echo](tls_echo.cc) | TLS server handshake and I/O | `tls_echo cert.pem key.pem [port]` (7443) |
| [unix_echo](unix_echo.cc) | Unix stream sockets (FreeBSD/Linux/macOS) | `unix_echo [path]` |
| [quic_echo_server](quic_echo_server.cc) | QUIC streams and DATAGRAMs | `quic_echo_server port cert.pem key.pem alpn` |
| [routing_server](routing_server.cc) | HTTP routes and static files | `routing_server [port] [document-root]` (8080) |
| [websocket_echo_server](websocket_echo_server.cc) | WebSocket upgrade over HTTP/1.1 | `websocket_echo_server [port]` (7001) |
| [websocket_routing_server](websocket_routing_server.cc) | Routed WebSockets over TLS HTTP/2 and HTTP/3 | `websocket_routing_server cert.pem key.pem [port]` (8443) |
| [websocket_client](websocket_client.cc) | Outbound WebSocket echo | `websocket_client ws-or-wss-url [message]` |

[port.h](port.h) holds the port argument shared by the servers.

## WebSocket client

```sh
./build/websocket_client wss://echo.websocket.org/ "hello"
```

The client accepts `ws://` and `wss://` URLs, resolves numeric IPv4/IPv6 or
DNS names on the bounded worker, verifies system-trusted TLS certificates and
hostnames, validates the HTTP upgrade, sends a masked text frame, and checks
one echoed text message. It skips up to 16 preceding control or greeting
frames. It limits messages to 4096 bytes and does not support fragmented
messages, redirects, proxies, or a reusable client API.

Probe five public echo URLs (the list is in the script), or pass your own;
the script exits nonzero if any server fails to echo the exact message:

```sh
python3 tests/probe_websocket_client.py --client ./build/websocket_client
```

The local handshake regression accepts lowercase HTTP field names and a
mixed-case `Upgrade` token, and sends a greeting before the echo:

```sh
python3 tests/run_websocket_client_headers.py --client ./build/websocket_client
```
