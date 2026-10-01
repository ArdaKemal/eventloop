# eventloop

**C++23 networking with coroutines, explicit ownership, and memory limits you can plan around.**

`eventloop` lets a connection read, write, wait, and recover in ordinary
coroutine control flow. The event loop keeps I/O and resumption on the owning
thread; bounded frame pools and queues make resource exhaustion visible instead
of allowing an unplanned heap fallback. The result is a useful foundation for
network services that need both straightforward application code and predictable
behavior under load.

The library includes awaitable TCP, TLS, and UDP sockets; HTTP/1.1 and TLS
HTTP/2 servers and an HTTP/2 client for one request per connection; WebSocket
framing; bounded file I/O; and a public QUIC v1/v2 endpoint API. It has Linux
epoll, macOS kqueue, and Windows IOCP backends.

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
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j2
ctest --test-dir build --output-on-failure
```

Start the echo server on loopback port 7000:

```sh
./build/tcp_echo 7000
```

Or serve a directory over plain HTTP:

```sh
./build/http_server --root ./public --http-only --http-port 8080
```

For HTTPS, provide a PEM certificate chain and private key:

```sh
./build/http_server --root ./public \
  --certificate certificate-chain.pem --private-key private-key.pem \
  --https-port 8443 --http-port 8080
```

The HTTPS listener negotiates HTTP/2 or HTTP/1.1. In this configuration the
plain HTTP listener redirects to HTTPS. Run `http_server --help` for the
available address, hostname, directory listing, and shutdown options. On
Windows, use a Visual Studio CMake generator and run programs from the build
configuration directory, such as `build/Release/http_server.exe`.

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
| HTTP and WebSocket | `http/server.h`, `ws/web_socket.h` | `http_server`, `websocket_echo_server`, `websocket_client` |
| Bounded file operations | `file_io.h` | `file_io_benchmark` |
| QUIC streams and DATAGRAMs | `quic.h` | `quic_echo_server`, `http3_client` |

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
separately; the HTTP client examples do so on a bounded worker.

## Protocol scope

- The static-file server supports HTTP/1.1 and TLS HTTP/2. It uses bounded
  request and response buffers and a component-by-component path walk that
  blocks symlink escapes. Linux plain HTTP uses `sendfile` for larger files.
- The outbound HTTP/2 client performs one HTTPS request per connection using
  ALPN `h2`. It supports general methods, bounded owned request bodies,
  streamed uploads, and streamed response bodies and headers. See
  [the API contract](docs/api-contract.md) for its limits and
  [the example](examples/http2_client.cc) for a public-header caller.
- WebSocket receive and send are awaitable and bounded by configured message
  and output limits. The [WebSocket client guide](examples/README-websocket-client.md)
  covers its outbound echo example.
- The public QUIC API supports v1/v2 connections, streams, and DATAGRAMs.
  The standalone `http3_client` exercises outbound HTTP/3. QUIC transport
  release qualification is still active; see the
  [milestone and remaining gates](docs/quic-milestone.md) and the
  [HTTP/3 verification guide](docs/http3-outbound-tests.md). The library does
  not include an HTTP/3 server.
- The HTTP server cancels active connection tasks on shutdown; its grace
  timeout does not drain unfinished responses.

Benchmark programs and harnesses live in `benchmark/`. They exercise local
workloads and are not throughput guarantees for other machines or networks.
