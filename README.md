# eventloop

C++23 coroutine networking with explicit ownership and bounded resource use.
Linux uses epoll, macOS and FreeBSD use kqueue, and Windows uses IOCP. I/O,
cancellation, and coroutine resumption run on the owning event-loop thread;
workers return completions to it.

## Build and run

Requires a C++23 compiler, CMake 3.20+, OpenSSL 3.5+, and threads.
On FreeBSD, use GCC 15 with the base OpenSSL 3.5.6: install the build and test
tools with `pkg install bash cmake curl gcc15 ninja`, then add `-G Ninja
-DCMAKE_CXX_COMPILER=g++15` to the configure command below. The base Clang 19
libc++ lacks C++23 library features used by eventloop.
The full HTTP/3 interop test needs an HTTP/3-capable curl; FreeBSD's package
lacks it, so configure with `-DCURL_EXECUTABLE=/path/to/curl`.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j2
ctest --test-dir build --output-on-failure
./build/tcp_echo 7000
```

[TCP echo](examples/basics/tcp_echo.cc) is a complete public-header server: it accepts
an owning `unique_fd`, transfers the stream to the loop, handles partial I/O
with a frame-local buffer, and closes sessions on completion or failure.
[Unix echo](examples/basics/unix_echo.cc) uses filesystem-path sockets on FreeBSD,
Linux, and macOS.
On Windows, use a Visual Studio CMake generator and run executables from the
build configuration directory. `EVENTLOOP_WINDOWS_TLS` defaults to `ON`;
turning it off omits TLS/WebSocket and HTTP/2 support, but still requires
OpenSSL for QUIC.

## Link from your project

```sh
cmake --install build --prefix /path/to/eventloop-install
```

```cmake
find_package(eventloop CONFIG REQUIRED)
target_link_libraries(your_app PRIVATE eventloop::eventloop)
```

Configure consumers with `-DCMAKE_PREFIX_PATH=/path/to/eventloop-install`.
Public headers are under `include/eventloop/`; readiness APIs remain private.

## APIs and examples

| API | Public header under `eventloop/` | Contract / caller |
| --- | --- | --- |
| Tasks, timers, composition, workers | `event_loop.h`, `task.h`, `task_composition.h`, `wakeup.h` | [Coroutines](docs/coroutines.md) |
| Bounded coroutine channel | `channel.h` | [Channel](docs/channel.md) |
| Scoped concurrency permits | `semaphore.h` | [Semaphore](docs/semaphore.md) |
| TCP | `tcp_acceptor.h`, `tcp_stream.h`, `ip_endpoint.h` | [TCP](docs/tcp.md), [echo](examples/basics/tcp_echo.cc) |
| TLS | `tls_stream.h`, `tls_context.h` | [TLS](docs/tls.md), [echo](examples/basics/tls_echo.cc) |
| Unix streams (FreeBSD/Linux/macOS) | `unix_socket.h` | [Unix sockets](docs/unix-sockets.md), [echo](examples/basics/unix_echo.cc) |
| UDP | `udp_socket.h` | [UDP](docs/udp.md) |
| QUIC v1/v2 streams and DATAGRAMs | `quic.h` | [QUIC](docs/quic.md), [echo](examples/basics/quic_echo_server.cc) |
| HTTP servers and routing | `http/server.h`, `http/http3_server.h`, `http/router.h` | [Shared HTTP](docs/http.md), [routing server](examples/basics/routing_server.cc) |
| HTTPS HTTP/2 client | `http2/client.h` | [Client contract](docs/http2.md#outbound-client), Wayfarer below |
| HTTP/3 client | `http3/client.h` | [Client contract](docs/http3.md#outbound-client), Wayfarer below |
| WebSocket | `ws/web_socket.h` | [WebSocket](docs/websocket.md), [client guide](examples/basics/README.md) |
| File I/O | `file_io.h` | [File I/O](docs/file-io.md) |
| Synchronous TOML configuration | `util/toml.h` | [TOML](docs/toml.md) |

The root build also produces the single-file programs in
[examples/basics](examples/basics/README.md). Standalone applications build
from their own example directories:

- [Wayfarer](examples/wayfarer/README.md): HTTP/1.1, HTTP/2, and HTTP/3 CLI
  client; redirects and file downloads.
- [Stonegate](examples/stonegate/README.md): file server with TOML defaults, includes, and
  named servers across all three protocols; TLS, redirects, directory listings,
  and a `/healthz` route.
- [Parley](examples/parley/README.md): browser chat, uploads, routed APIs,
  HTTP/2 WebSockets, and event-stream fallback.

Shared URL and DNS helpers for the client examples are in
`examples/client_support/`. Root test fixtures are in `tests/fixtures/`;
benchmarks are in `benchmark/`.
[Latency optimization](docs/latency-optimization.md) covers TCP/TLS and HTTP/2/3
experiments, measurement rules, and further optimization.
[API conventions](docs/api-conventions.md) guide API changes;
[the contract index](docs/api-contract.md) links shared rules and topic details.

## Ownership and limits

- Coroutine frames use configurable per-loop size classes with bounded slab
  growth; individual frames never fall back to the general heap. Queues,
  file workers, and protocol storage also have explicit limits and exhaustion
  results. Setup, slab growth, OpenSSL, and some request paths may allocate;
  allocation tests and exceptions are documented per protocol.
- Descriptors transferred as `unique_fd` are owned. Async spans and borrowed
  descriptors stay valid until completion, including after cancellation.
  Cancellation requests do not release frames or worker references.
  Keep observed `task_handle<T>` roots alive until `done()`.
- Socket endpoints are numeric IPv4/IPv6; applications resolve DNS separately.
  Wayfarer and the WebSocket client use a bounded worker for resolution.
- Shutdown cancels active roots immediately. Its grace timeout does not let
  built-in HTTP responses drain.

## Protocol scope

HTTP/1.1, TLS HTTP/2, and HTTP/3 share coroutine routing and secure static-file
traversal. Static responses support GET/HEAD/OPTIONS, validators, single byte
ranges, and bounded directory listings. Linux plain HTTP uses `sendfile` for
large files; TLS HTTP/1.1 and HTTP/2 can use transmit kTLS, with bounded
buffered fallback. See [shared HTTP](docs/http.md) and
[HTTP/1.1](docs/http1.1.md), [HTTP/2](docs/http2.md), or [HTTP/3](docs/http3.md).

The HTTP/2 client performs HTTPS requests with ALPN `h2`, bounded owned bodies
or streamed uploads/responses, one-shot or as sequential requests on a
connection reused across origins its certificate covers (RFC 9113 9.1.1). The
HTTP/3 client takes the same request and response types and carries sequential
requests on one QUIC connection. QUIC exposes v1/v2 endpoints, streams, and
DATAGRAMs. WebSocket framing is bounded; HTTP/2 and HTTP/3 CONNECT routes
can accept RFC 8441/9220 WebSockets. The
[routed echo example](examples/basics/websocket_routing_server.cc) exercises both.
Keep interoperability and performance claims scoped to the tested paths;
local benchmark workloads are not throughput guarantees.

## License

[MIT](LICENSE). Use it freely, but keep the copyright notice and license text
in copies and substantial portions, which credits the original author.
