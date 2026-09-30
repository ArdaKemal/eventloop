# Event loop

A small C++23 coroutine-native networking library with a Linux epoll event
loop, bounded coroutine runtime, TCP/TLS/UDP sockets, HTTP/1.1, TLS HTTP/2, and
WebSocket support. The echo protocols are examples built on the public
awaitable APIs.

## Layout

```text
include/eventloop/  Public event loop and TCP transport API
src/                Platform-independent implementations
src/linux/          Private Linux epoll backend
examples/           Programs built on top of the library
tests/              Plain/TLS transport integration coverage
```

```sh
cmake -S . -B build
cmake --build build
./build/tcp_echo 7000
```

The server listens on loopback. Stop it with `Ctrl-C`.

For the TLS echo example, provide a PEM certificate chain and private key:

```sh
./build/tls_echo certificate.pem private-key.pem 7443
```

Run the HTTP/1.1 static-file server with a document root and TLS certificate:

```sh
./build/http_server \
    --root ./public \
    --certificate certificate-chain.pem \
    --private-key private-key.pem \
    --hostname example.com \
    --http-port 80 \
    --https-port 443
```

The HTTP listener redirects requests to HTTPS. The HTTPS listener serves files
and uses `index.html` for directories. Pass `--directory-listing` to generate a
listing when a directory has no index file. Run `http_server --help` for all
options. `SIGINT` and `SIGTERM` request event-loop shutdown. Active coroutine
roots are cancelled and built-in socket handlers close immediately, including
HTTP connections with unfinished responses. `--shutdown-timeout` bounds any
handlers still registered after shutdown notification; a second signal forces
their removal immediately.

HTTPS advertises HTTP/2 (`h2`) and HTTP/1.1 through ALPN by default. HTTP/2
serves GET, HEAD, and OPTIONS requests, supports concurrent streams, and keeps
request frames, HPACK tables, streams, and queued inline bodies bounded. Large
regular files stream within HTTP/2 flow control. Cleartext HTTP and HTTP/1.1
Upgrade to h2c are not supported; the plain HTTP listener remains HTTP/1.1.

To serve plain HTTP without TLS or a redirect listener, certificate files are
not required:

```sh
./build/http_server --root ./public --http-only --http-port 8080
```

The standalone HTTP client example sends one HTTP/1.1 GET request and writes
the complete response to standard output. It accepts `http://` and `https://`
URLs, including bracketed IPv6 addresses; HTTPS verifies the server using the
system trust store:

```sh
./build/http_client https://example.com/path
./build/http_client 'http://[::1]:8080/'
```

The HTTP parser and request/response path use fixed-capacity buffers. Requests
larger than those limits receive an appropriate 4xx response instead of
growing buffers dynamically.

Run the transport tests with:

```sh
ctest --test-dir build --output-on-failure
```

## Coroutine composition

The [coroutine API contract](docs/api-contract.md) describes ownership,
results, cancellation, and capacity rules for new coroutine-facing APIs.
Use `eventloop::task_handle<T>` with
`eventloop::event_loop::spawn(task<T>, handle)` to observe a root task's result.
The handle can be awaited once or queried with `done()`
and `take_result()`. Its `cancel()` method requests cancellation on the owning
loop thread; keep the handle alive until completion, including when worker or
file I/O must retire. An active handle cannot be moved or destroyed.

Include `eventloop/task_composition.h` for `when_all(task<T>...)`,
`race(task<T>...)`, and `with_timeout(loop, task<T>, duration)`.
`task<T>` returns `std::expected<T, task_result>` when awaited; `task<void>`
continues to return `task_result`. A child whose value is itself
`std::expected` retains that value and its error unchanged.

`when_all` returns a tuple of child results after every child has finished.
`race` returns the first completion's index and result, then requests
cancellation of the other branches and waits for them to retire before
returning. An already cancelled parent receives `task_result::cancelled`.
`with_timeout` returns `completed`, `timed_out`, or `cancelled`; a zero or
negative duration times out without starting the operation. Cancellation of
worker or file I/O waits for its completion before releasing the child's
frame, so a timeout can take longer than its deadline.

Operands must be unstarted tasks belonging to the same loop. Each branch and
the combinator's parent use that loop's bounded coroutine frames. The arity is
fixed at compile time; large combinations may exceed the largest frame class
and report `frame_allocation_failure`. The combinators do not accept arbitrary
third-party awaitables; use them inside a `task<T>` instead.

## Coroutine file I/O

Include `eventloop/file_io.h` to `co_await` `async_openat`, `async_read_at`, or
`async_write_at` from a task owned by an `event_loop`. Operations run on a
dedicated bounded worker and post completion back to the same event loop.
`file_io_depth` bounds concurrent file operations; a full queue returns
`EAGAIN`.

The operations return `std::expected` with `std::error_code` on failure.
`async_openat` returns an owning `unique_fd` and copies paths up to 255 bytes
into the coroutine frame. The directory and file descriptors passed to these
operations are borrowed and must remain open and unreused until completion,
including after cancellation is requested. Read and write buffers must remain
valid for the same period. Cancellation does not abort an already-running
syscall; the coroutine resumes with `ECANCELED` after that syscall completes.
The current event-loop implementation itself remains Linux/epoll-only.

## Coroutine socket I/O

Include `eventloop/tcp_acceptor.h` and `eventloop/tcp_stream.h` for nonblocking
IPv4 or IPv6 TCP, `eventloop/tls_stream.h` for TLS, or `eventloop/udp_socket.h`
for datagrams. Public types live in `eventloop`; HTTP and WebSocket types
live in `eventloop::http` and `eventloop::ws`. TCP and UDP addresses use
`eventloop::ip_endpoint`, with address octets, a host-order port, and an IPv6
scope ID. Use its `from_ipv4`/`from_ipv6`, `loopback_v4`/`loopback_v6`,
`any_v4`/`any_v6`, or numeric `parse` factories. IPv6 sockets are v6-only.
`eventloop::event_loop::add` takes ownership of supported socket objects.
Await `async_accept`, `async_connect`, `async_read_some`, `async_write_some`,
and the UDP send/receive operations. TCP reads and writes may complete
partially; UDP operations preserve datagram boundaries. Buffers remain
caller-owned through completion, including cancellation. Call `close()` to
cancel pending operations and remove a socket from its loop.

The public asynchronous I/O APIs are coroutine based. Readiness dispatch stays
inside the event-loop implementation. `post()` remains available for bounded
commands that cross into the loop thread.

The HTTP server also uses connection coroutines. Its parser and response
buffers live in a session owned by each connection task. Plain HTTP retains
`sendfile` for larger files; metadata and small-file reads remain synchronous.

`./build/file_io_benchmark` measures cached 4 KiB reads at 16-way concurrency
and reports operation throughput/latency plus event-loop timer lateness. It is
an executor and event-loop overhead probe, not a storage-device benchmark.

`./build/coroutine_socket_benchmark both 10000 16` runs 16 concurrent clients
through 64-byte TCP and UDP loopback echo workloads. Pass `tcp` or `udp` as the
first argument to profile one transport. This measures coroutine, epoll,
syscall, and local kernel networking costs; it does not measure NIC throughput.
For a symbolized CPU profile, build with `RelWithDebInfo` and frame pointers,
then record either transport with:

```sh
cmake -S . -B build-profile -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_CXX_FLAGS_RELWITHDEBINFO='-O2 -g -DNDEBUG -fno-omit-frame-pointer'
cmake --build build-profile --target coroutine_socket_benchmark -j2
perf record -F 997 -g --call-graph fp -o /tmp/eventloop-tcp.data -- \
  ./build-profile/coroutine_socket_benchmark tcp 10000 16
perf report --stdio -i /tmp/eventloop-tcp.data
```

## HTTP throughput comparison

On Debian/Ubuntu, install `wrk`, `nginx`, and `lighttpd`, then run:

```sh
./benchmark/http-throughput.sh
```

The harness builds the HTTP example in `Release` mode if necessary, generates
one static payload, and runs each server on loopback with one worker and the
same `wrk` keep-alive workload. It warms each server before reporting `wrk`'s
requests/sec, transfer/sec, and latency. Defaults are a 4 KiB payload, 128
connections, one `wrk` thread, and a 15-second measurement. Override them for
additional profiles, for example:

```sh
FILE_SIZE=1024 CONNECTIONS=256 DURATION=30s ./benchmark/http-throughput.sh
```

Use `SERVER=eventloop`, `SERVER=nginx`, or `SERVER=lighttpd` to repeat one
participant while diagnosing a result.

This is a local HTTP/1.1 static-file benchmark, not a production tuning guide.
Plain HTTP file responses use Linux `sendfile`; HTTPS responses pass through
OpenSSL in user space. Plain HTTP files smaller than 11 KiB use the buffered path;
larger files use `sendfile`. Treat the comparison as end-to-end baseline data
and record the command, CPU, and package versions with any result.

### Listener-thread scaling

`http_benchmark_server` accepts an optional thread count. Each listener thread
runs its own event loop and binds the port with `SO_REUSEPORT`, so the kernel
spreads accepted connections across the loops. To measure the bundled server as
that count grows:

```sh
SERVER_THREADS="1 2 4 8" ./benchmark/http-scaling.sh
```

To compare the bundled server with nginx and lighttpd at several worker counts
under the same workload:

```sh
WORKERS="1 8" ./benchmark/http-multicore.sh
```

Both harnesses pin the server to `SERVER_CPUS` (default `0-7`) and `wrk` to
`CLIENT_CPUS` (default `8-15`) so the load generator and the server do not
contend for the same cores. They otherwise accept the same `DURATION`,
`CONNECTIONS`, `WRK_THREADS`, and `FILE_SIZE` overrides as the throughput
comparison.
