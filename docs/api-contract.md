# Coroutine API contract

Public asynchronous I/O uses C++ coroutines. Core public names live in
`eventloop`, HTTP names in `eventloop::http`, and WebSocket names in
`eventloop::ws`. Platform readiness machinery is an internal implementation
detail; applications register the library's TCP, TLS, and UDP objects with
`eventloop::event_loop`, then await their operations. `post()` and executor
submissions remain bounded command and background-work APIs.

QUIC endpoints reserve 80 stream slots per connection: 32 bidirectional and
8 unidirectional streams for each initiator. Requested advertised counts are
capped to those peer reservations; local opens obey the peer's grant and the
separate local reservation. Increasing peer `MAX_STREAMS` grants cannot
enlarge local storage. These are cumulative lifetime limits: completed and
reset streams retain their slots, and closing a stream does not replenish its
quota. The aggregate receive-data window remains at most 128 KiB, independently
of stream count, with at most 4 KiB buffered per stream. No stream storage falls
back to an unbounded allocation.

## Ownership and thread affinity

- A coroutine function returning `eventloop::task<T>` takes its owning
  `eventloop::event_loop&` as its first argument. Started tasks, their frames,
  awaiters, cancellation, and resumption stay on that loop's thread.
- A task is move-only. Start it once by awaiting or spawning it. Destroying an
  unfinished started task is a programming error. Coroutine frames come from
  bounded per-loop size classes. Each class has a warm reserve and a hard slot
  limit; the pool adds backing slabs on demand and releases growth slabs when
  they become empty. Individual frames never fall back to the general heap.
- `eventloop::event_loop::add` accepts owning pointers to
  `eventloop::tcp_acceptor`, `eventloop::tcp_stream` (including
  `eventloop::tls_stream`), and `eventloop::udp_socket`. It does not accept
  application readiness handlers. Call an object's `close()` to cancel its
  pending socket operations and deregister it. A pointer to a loop-owned object becomes invalid
  after `close()` removes it or after an operation removes it on failure.
- `eventloop::event_loop::spawn(eventloop::task<void>)` transfers a
  fire-and-forget root to the loop. Its overload taking `eventloop::task<T>`
  and `eventloop::task_handle<T>&` transfers an observed root. The handle is a
  stable scope and must remain alive until `done()`. It may have
  one awaiting coroutine; otherwise consume its result with `take_result()`.
- `eventloop::task_handle<T>::cancel`, `done`, `take_result`, and `co_await` are
  loop-thread operations. Other threads submit commands with bounded
  `eventloop::event_loop::post` and must check its return value.
- `task_executor()` runs independent work away from the loop. Worker code must
  not access loop-owned objects; use `post()` or the coroutine blocking/file
  operations to return work to the loop safely.

## Results and errors

- Awaiting `eventloop::task<T>` yields
  `std::expected<T, eventloop::task_result>`. Awaiting
  `eventloop::task<void>` yields `eventloop::task_result`. A task whose value
  is itself an `std::expected` preserves that inner result; the outer result
  describes task infrastructure such as frame exhaustion.
  `eventloop::flatten_result` turns an
  `std::expected<std::expected<T, std::error_code>, task_result>` into the
  inner expected without allocating. It maps frame exhaustion to
  `not_enough_memory` and cancellation to `operation_canceled`, including for
  `void` and move-only values.
- Syscall-like socket and file operations return
  `std::expected<T, std::error_code>`. A cancelled pending I/O operation
  reports `ECANCELED`, equivalent to `std::errc::operation_canceled` in the
  generic error category. This is separate from
  `eventloop::task_result::cancelled`, which describes a task result. A full
  bounded queue or operation pool
  returns an error rather than allocating an unbounded replacement.
- `eventloop::task<T>::result()` and
  `eventloop::task_handle<T>::take_result()` consume stored
  values once. Unhandled exceptions in a task currently terminate the
  process; return anticipated application errors as values.
- Destroy the event loop only after all coroutine frames have retired. The
  loop checks this before destroying its worker and poller state.
- `eventloop::yield`, `eventloop::sleep_for`, `eventloop::sleep_until`, and
  `eventloop::run_blocking` check loop affinity. Wrong-loop use is a
  programming error.

## Cancellation and timers

- Cancellation is a request, not proof that work has stopped. A task may
  complete normally after cancellation; `eventloop::task_handle<T>::cancel()` does not mark
  its result as cancelled or release its frame.
- Cancelling a timer retires it immediately. A worker or file operation may
  still hold references into a coroutine frame; its completion must reach the
  loop before the frame is destroyed. `eventloop::race` and
  `eventloop::with_timeout` follow this rule and wait for losing branches to
  retire.
- `eventloop::sleep_for` and `eventloop::sleep_until` are the public timer
  interface. Positive relative durations saturate at the latest representable
  time point; zero or negative durations are immediately due. Callback timer scheduling is not a
  public API.
- `eventloop::event_loop::shutdown(timeout)` stops new registrations and
  requests cancellation of every active root immediately. It then calls
  `on_shutdown()` on registered handlers; the built-in acceptors and streams close immediately.
  The timeout bounds only handlers still registered after notification and
  does not provide a response-draining period for built-in HTTP connections.
  A second call forces removal of any remaining handlers immediately.

## TCP and TLS

- Include `eventloop/tcp_acceptor.h` and `eventloop/tcp_stream.h` for
  nonblocking IPv4 or IPv6 TCP. Use `eventloop::ip_endpoint` for numeric
  addresses. IPv6 sockets are v6-only; `parse()` accepts numeric IPv6 scope
  IDs after `%`.
  Add each object to its loop before awaiting it.
  `eventloop::tcp_acceptor::async_accept()` returns an owned
  `eventloop::unique_fd`; `eventloop::tcp_stream::async_connect()`,
  `async_read_some()`, and `async_write_some()` return `std::expected`
  results. Reads and writes may complete partially.
- Caller-owned buffers remain valid until their await completes, including
  after cancellation is requested. At most one read, one write, one connect,
  and one send-file operation may be pending per TCP stream.
- A second pending connect attempt reports `EALREADY`. An immediate connect
  error leaves the stream registered so the caller can inspect the result and
  close it. A pending connect failure or cancellation removes the stream.
  Check saved descriptors or task results before retaining
  a pointer after failure.
- `eventloop::tcp_stream::async_send_file()` takes ownership of its file
  descriptor and sends the optional header followed by the requested file
  range. Plain HTTP uses it for larger files; preserve the component-by-component `O_NOFOLLOW` path walk that protects document-root access.
- `eventloop::tls_stream` adds `async_handshake`, `async_read_some`,
  `async_write_some`, and `async_close`. Await `async_close()` to flush TLS
  `close_notify`, then call `close()` to retire the transport. `close()` itself immediately
  cancels operations and closes the transport. One TLS read and one TLS write
  may be pending together. A second read or second write returns `EBUSY`.
  Handshake and `async_close()` require all other TLS operations to be idle.
  For outbound TLS, construct with an `ip_endpoint`, a client context, and
  `tls_client_options` containing the verification hostname; await inherited
  `async_connect()` before `async_handshake()`. The hostname also supplies SNI,
  and `application_protocols` configures ALPN. A handshake on an unconnected
  socket returns `ENOTCONN`. Raw TCP `async_send_file()` is hidden from
  `tls_stream` because it would bypass TLS framing.

## UDP and WebSocket

- Include `eventloop/udp_socket.h` for IPv4 or IPv6 datagrams using
  `eventloop::ip_endpoint`. Datagrams stay atomic:
  empty datagrams succeed with size zero, and a truncated receive consumes the
  datagram and reports `EMSGSIZE`. At most one receive and one send may be
  pending per socket; a duplicate same-direction operation reports `EBUSY`.
- The WebSocket API is `eventloop::ws::web_socket<Stream>` over a stream with
  coroutine read/write operations. Use `async_receive`, `async_send_text`,
  `async_send_binary`, and `async_close`. One receive and one send may run
  concurrently. A returned payload view remains valid until the next receive
  or socket destruction; send buffers remain caller-owned until completion.
- WebSocket framing is bounded by the configured message limit plus frame and
  control overhead. Errors retire the parser/output state and close the
  transport. Fan-out helpers are best-effort: a full recipient drops only the
  current message and the result counts those drops.

## Composition and file I/O

- Include `eventloop/task_composition.h` for fixed-arity `eventloop::when_all`,
  `eventloop::race`, and `eventloop::with_timeout`. Operands must be unstarted
  tasks belonging to the same loop. Large combinations may exceed the largest
  frame class and report `frame_allocation_failure`.
- Include `eventloop/file_io.h` for `eventloop::async_openat`,
  `eventloop::async_read_at`, and `eventloop::async_write_at`.
  `eventloop::async_openat` returns an owning `eventloop::unique_fd` on success.
  Paths are copied into a bounded awaiter buffer. The directory descriptor
  passed to `async_openat` and file descriptors passed to `async_read_at` and
  `async_write_at` are borrowed; callers must keep them open and unreused until
  completion, including after cancellation. Read and write buffers remain
  caller-owned and valid for the same period. Operations run on a dedicated
  bounded worker; a full `file_io_depth` returns an error.
- HTTP accept loops spawn connection tasks. Each task owns its session and I/O
  buffers while suspended; accepted connections share ownership of the
  document-root descriptor with the listener. Small file reads and metadata
  calls remain synchronous; large plain HTTP files use `sendfile`. Preserve
  the component-by-component `O_NOFOLLOW` path walk.
- `eventloop::http::https_server` advertises `h2` and `http/1.1` with ALPN by
  default. Set `eventloop::http::server_options::enable_http2` to `false` to
  disable HTTP/2. The
  HTTP/2 path serves GET, HEAD, and OPTIONS over TLS, supports up to 32 active
  streams per connection, decodes bounded HPACK header blocks, and observes
  connection and stream DATA flow control. Request bodies are discarded and
  limited to 1 MiB. File responses stream from their owned descriptors; inline
  response bodies are bounded to 4 MiB per connection. Directory-root traversal
  shares HTTP/1.1's component-by-component `O_NOFOLLOW` checks. Cleartext
  prior-knowledge HTTP/2, h2c upgrade, CONNECT tunnels, and extended CONNECT are
  not supported. Plain `http::server` continues to serve HTTP/1.1.
- Include `eventloop/http2/client.h` for one outbound HTTPS HTTP/2 request.
  `http2::async_request(loop, endpoint, context, hostname, request)` owns the
  TLS socket from connect through close. `hostname` is used for certificate
  verification, SNI, and the default `:authority`; `endpoint` is a numeric
  address, so name resolution belongs to the caller. ALPN must select `h2`.
  Requests own their method, target, authority override, header strings, and
  body bytes or a `request_body_source` callback. Any valid HTTP method token
  is accepted, including GET, HEAD, POST, PUT, PATCH, DELETE, and OPTIONS.
  The owned body is limited to 4 MiB; a source can produce up to 1 TiB in
  chunks of at most 16 KiB. Set either the owned body or the source. The source
  is task-owned and called on the loop thread with a writable borrowed span;
  it returns 0 for EOF, a byte count within the span, or an operation error.
  Resources captured by the source must remain valid through completion,
  including cancellation. `Content-Length` is optional and can be supplied as
  a request header when known. DATA transmission observes the peer's connection
  and stream flow-control windows. Responses own status and headers. The
  five-argument operation owns the response body, capped at 4 MiB. Passing a
  sixth `response_sink` argument
  streams DATA chunks synchronously to that callback on the loop thread;
  `response.body` is then empty. A sink receives a borrowed chunk valid only
  during the call and returns `std::error_code`; a nonzero result aborts the
  request and becomes the operation error. An optional seventh
  `response_header_sink` receives each complete header block before subsequent
  DATA: its status argument is 1xx for informational headers, the final HTTP
  status for final headers, and zero for trailers. The fields span is borrowed
  only during the call; a nonzero callback error aborts the request. Final
  response headers and trailers remain owned in the returned response.
  Streamed response bodies are limited to 1 TiB while buffering remains one
  16 KiB frame. The operation uses one
  stream per connection. Connection reuse and server push are outside its scope.
  Request and response header blocks are limited to 64 KiB and 128 fields.
  Frames from the server are limited to 16 KiB as advertised in client
  SETTINGS. Reaching
  a limit returns `message_size`; malformed HTTP/2 returns `protocol_error`.
  Each request allocates its own bounded frame, header, and response storage;
  TLS and OpenSSL may allocate separately.
  A TLS connect, handshake, read, or write error is returned directly; task
  cancellation closes the owned transport. All I/O and resumption occur on
  `loop`, and the outer task result remains distinct from the operation error.
- `eventloop::http::http3_server` listens on a QUIC UDP endpoint with ALPN
  `h3`, a certificate/key pair, and an owned document-root descriptor. Its
  `run()` task accepts connections; `close()` stops acceptance and
  `async_close()` waits for endpoint retirement. Keep the server and its
  observed `run()` task alive until both operations complete. GET, HEAD, and
  OPTIONS serve static files or `index.html` using the shared secure resource
  walk. Request header blocks are capped at 16 KiB and 128 fields, dynamic
  QPACK tables are disabled, and QUIC caps each connection at 32 peer
  bidirectional and eight peer unidirectional streams. A request that exceeds
  the header cap closes its connection. Directory listings, request bodies,
  HTTP/3 server push, and WebTransport are not supported.
