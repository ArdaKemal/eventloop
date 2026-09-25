# Event loop

A small C++23 event loop with an epoll backend and reusable asynchronous TCP
transport classes. The echo protocol is implemented separately as a demo.

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
options. `SIGINT` and `SIGTERM` stop the listeners, close idle connections, and
allow active responses up to five seconds to finish. Use `--shutdown-timeout`
to change that deadline; a second signal closes remaining connections at once.

To serve plain HTTP without TLS or a redirect listener, certificate files are
not required:

```sh
./build/http_server --root ./public --http-only --http-port 8080
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
Use `task_handle<T>` with `event_loop::spawn(task<T>, handle)` to observe a
root task's result. The handle can be awaited once or queried with `done()`
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
`async_write_at` from a task owned by an `event_loop`. On Linux with
liburing available, the first file operation attempts an io_uring backend;
otherwise it uses a dedicated worker and posts completion back to the same
event loop. Set `event_loop_options::file_backend` to `executor` or `io_uring`
to force a backend. Forcing io_uring reports setup failure instead of silently
falling back. `file_io_depth` bounds concurrent file operations; a full backend
returns `EAGAIN`.

The operations return `std::expected` with `std::error_code` on failure.
`async_openat` copies paths up to 255 bytes into the coroutine frame. Read and
write buffers must remain valid until completion, including after cancellation
is requested. Cancellation does not abort an already-running syscall; the
coroutine resumes with `ECANCELED` after that syscall completes. The current
event-loop implementation itself remains Linux/epoll-only; the worker fallback
also covers Linux systems where io_uring is unavailable or disallowed.

`./build/file_io_benchmark` compares the two backends using cached 4 KiB
reads at 16-way concurrency and reports operation throughput/latency plus
event-loop timer lateness. It is a backend-overhead probe, not a storage-device
benchmark; run it outside a sandbox that blocks `io_uring_setup` to measure
both backends.

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
Botan in user space. Plain HTTP files smaller than 11 KiB use the buffered path;
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
