# eventloop

**C++23 networking with coroutines, explicit ownership, and memory limits you can plan around.**

`eventloop` lets a connection read, write, wait, and recover in ordinary
coroutine control flow. The event loop keeps I/O and resumption on the owning
thread; bounded frame pools and queues make resource exhaustion visible instead
of allowing an unplanned heap fallback. The result is a useful foundation for
network services that need both straightforward application code and predictable
behavior under load.

The library provides awaitable TCP, TLS, UDP, and Unix domain stream operations
(Unix sockets on Linux and macOS); QUIC endpoints
and streams; HTTP/1.1, TLS HTTP/2, and HTTP/3 static-file servers; a bounded HTTP/2
client API; WebSocket framing; and bounded file I/O. It has Linux epoll,
macOS kqueue, and Windows IOCP backends.

For a local stream service, use `unix_acceptor` and `unix_stream` from
`eventloop/unix_socket.h`. [unix_echo](examples/unix_echo.cc) shows a complete
server. The listener removes its socket path on close if that path still names
its socket; it never removes an existing path before bind.

Two applications show how these pieces work together using public headers:
[Wayfarer](examples/wayfarer/README.md) fetches over HTTP/1.1, HTTP/2, or
HTTP/3, while [Stonegate](examples/stonegate/README.md) serves a document root
over the same protocol generations. They build as separate example projects,
keeping the core library's examples small.

## A complete echo server

This small server accepts TCP connections on loopback and echoes each byte
back. The event loop owns the listener and streams. Each connection gets a
coroutine with a 512-byte buffer in its bounded frame:

```cpp
#include <array>
#include <chrono>
#include <cstddef>
#include <memory>
#include <span>
#include <utility>

#include "eventloop/event_loop.h"
#include "eventloop/task.h"
#include "eventloop/tcp_acceptor.h"
#include "eventloop/tcp_stream.h"

using namespace eventloop;

auto echo_session(event_loop& loop, tcp_stream& stream) -> task<void>
{
    (void)loop;
    std::array<std::byte, 512> buffer{};

    for (;;) {
        auto received = co_await stream.async_read_some(buffer);
        if (!received || *received == 0) break;

        std::size_t offset = 0;
        while (offset < *received) {
            auto sent = co_await stream.async_write_some(
                std::span<const std::byte>(buffer)
                    .first(*received).subspan(offset));
            if (!sent || *sent == 0) {
                stream.close();
                co_return;
            }
            offset += *sent;
        }
    }
    stream.close();
}

auto serve(event_loop& loop, tcp_acceptor& listener) -> task<void>
{
    for (;;) {
        auto accepted = co_await listener.async_accept();
        if (!accepted) co_return;

        auto stream = std::make_unique<tcp_stream>(loop, std::move(*accepted));
        auto* session = stream.get();
        loop.add(std::move(stream));
        if (loop.spawn(echo_session(loop, *session)) != task_spawn_result::accepted)
            session->close();
    }
}

int main()
{
    event_loop loop;
    auto acceptor = std::make_unique<tcp_acceptor>(
        loop, ip_endpoint::loopback_v4(7000));
    auto* listener = acceptor.get();
    loop.add(std::move(acceptor));

    if (loop.spawn(serve(loop, *listener)) != task_spawn_result::accepted) {
        listener->close();
        return 1;
    }
    if (loop.run() == event_loop_result::interrupted) {
        loop.shutdown(std::chrono::seconds{0});
        (void)loop.run();
    }
}
```

The read and write calls may complete partially, so the session handles both
cases. Closing a stream cancels its pending operations and removes it from the
loop. The full [TCP echo example](examples/tcp_echo.cc) adds port parsing and
error reporting. Build and run that example with the commands below.

## Build and run

You need a C++23 compiler, CMake 3.20 or newer, OpenSSL 3.5 or newer, and
thread support.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build -j2
```

Tests are enabled by default, but their executables and HTTP fixtures are
excluded from normal builds. Run final verification explicitly:

```sh
cmake --build build --target check -j2
```

The `check` target builds the test executables and then runs CTest. It does not
require Python, aioquic, h2, websockets, curl, or an external QUIC stack.
On Unix, the TLS loopback check uses Bash and the OpenSSL command line tool. Subsequent
runs reuse the existing build. `-DBUILD_TESTING=OFF` omits tests and the `check`
target entirely.

Start the echo server on loopback port 7000:

```sh
./build/tcp_echo 7000
```

For a more complete HTTP example, build Stonegate and Wayfarer from the same
checkout:

```sh
cmake -S examples/stonegate -B /tmp/stonegate-build -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/stonegate-build --target stonegate -j2
cmake -S examples/wayfarer -B /tmp/wayfarer-build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
cmake --build /tmp/wayfarer-build --target wayfarer -j2
```

Serve a local directory and fetch its index page:

```sh
mkdir -p /tmp/stonegate-root
printf 'hello from eventloop\n' > /tmp/stonegate-root/index.html
/tmp/stonegate-build/stonegate --root /tmp/stonegate-root --http-port 8080
```

In another terminal:

```sh
/tmp/wayfarer-build/wayfarer http://127.0.0.1:8080/
```

Stonegate can also enable TLS HTTP/1.1 and HTTP/2 and serve HTTP/3 over UDP
with a certificate and private key. Wayfarer can select HTTP/2 or QUIC v1/v2
HTTP/3 explicitly, follow redirects, and save completed downloads to a file.
Their guides cover the commands and limits. On Windows, use a Visual Studio
CMake generator and run programs from the build configuration directory.

## Use it in your project

Install the library and link the exported CMake target:

```sh
cmake --install build --prefix /path/to/eventloop-install
```

```cmake
find_package(eventloop CONFIG REQUIRED)
target_link_libraries(your_app PRIVATE eventloop::eventloop)
```

Pass `-DCMAKE_PREFIX_PATH=/path/to/eventloop-install` when configuring a
consumer outside CMake's usual package search paths. Public headers are under
`include/eventloop/`.

| Build with | Public entry point | Runnable example |
| --- | --- | --- |
| TCP and TLS services | `tcp_acceptor.h`, `tcp_stream.h`, `tls_stream.h` | `tcp_echo`, `tls_echo` |
| UDP services | `udp_socket.h`, `ip_endpoint.h` | `coroutine_socket_benchmark` |
| HTTP client | `http2/client.h`, TCP/TLS and QUIC APIs | [Wayfarer](examples/wayfarer/README.md) |
| HTTP server | `http/server.h`, `http/http3_server.h` | [Stonegate](examples/stonegate/README.md) |
| WebSocket | `ws/web_socket.h` | `websocket_echo_server`, `websocket_client` |
| Bounded file operations | `file_io.h` | `file_io_benchmark` |
| QUIC streams and DATAGRAMs | `quic.h` | `quic_echo_server` |
| TOML configuration | `util/toml.h` | — |

The older single-protocol HTTP programs needed by the root integration tests
live under `tests/fixtures/`. Benchmark-only programs live under `benchmark/`.

For configuration files, `eventloop::util::parse_toml` parses
[TOML 1.1.0](https://toml.io/en/v1.1.0) into caller-provided node and decoded
string buffers. The document borrows those buffers and the input; exhaustion
returns an error. Parsing is synchronous and portable. See the
[TOML API contract](docs/api-contract.md#toml-configuration-parsing) for
storage lifetimes, limits, and error behavior.

The library also provides `task<T>`, observed `task_handle<T>` roots,
`when_all`, `race`, and `with_timeout` for composing loop-owned work.
The [coroutine API contract](docs/api-contract.md) explains task results,
cancellation, buffer lifetimes, and capacity errors. The
[API conventions](docs/api-conventions.md) describe how public operations fit
together.

## Designed for bounded services

Coroutine frames come from configurable, per-loop size classes. Socket
awaiters use caller-owned buffers and frame-local state; file operations run
on a dedicated bounded worker. Queues and protocol buffers have limits, and
operations report when a limit is reached. OpenSSL and setup code may allocate,
so the library does not promise a heap-free process.

Ownership is visible at the API boundary. For example, accepting a TCP
connection returns an owning `unique_fd`, while a `std::span` passed to an
asynchronous read remains the caller's buffer until completion. Cancellation
is a request; an in-flight worker or I/O operation must retire before its
frame and borrowed inputs can be released. Event-loop objects and their
coroutines stay on the owning thread.

The socket APIs use numeric IPv4 and IPv6 endpoints. Applications resolve DNS
separately; Wayfarer and the WebSocket client do so on a bounded worker.

## Protocol scope

- The static-file server APIs support HTTP/1.1, TLS HTTP/2, and HTTP/3.
  Stonegate composes them into one configurable program. File access uses
  bounded buffers and a component-by-component path walk that blocks symlink
  escapes. Stonegate supports conditional requests, single byte ranges, and
  bounded directory listings. Linux plain HTTP uses `sendfile` for larger
  files. HTTPS HTTP/1.1 and HTTP/2 use OpenSSL kTLS `sendfile` for file
  responses when transmit kTLS is active for the connection, with bounded
  buffered paths otherwise.
- The outbound HTTP/2 client performs one HTTPS request per connection using
  ALPN `h2`. It supports general methods, bounded owned request bodies,
  streamed uploads, and streamed response bodies and headers. See
  [the API contract](docs/api-contract.md) for its limits and
  [Wayfarer](examples/wayfarer/README.md) for a public-header caller.
- WebSocket receive and send are awaitable and bounded by configured message
  and output limits. The [WebSocket client guide](examples/README-websocket-client.md)
  covers its outbound echo example.
- The public QUIC API supports v1/v2 connections, streams, and DATAGRAMs.
  Wayfarer and Stonegate exercise the client and server sides of HTTP/3.
  QUIC transport release qualification is still active. Optional independent
  HTTP/3 checks are described in the Wayfarer and Stonegate guides.
- The HTTP server cancels active connection tasks on shutdown; its grace
  timeout does not drain unfinished responses.

Benchmark programs and harnesses live in `benchmark/`. They exercise local
workloads and are not throughput guarantees for other machines or networks.
The [single-thread performance report](docs/single-thread-performance.md)
records executor, post, timer, and UDP measurements with reproducible commands.
