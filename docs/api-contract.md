# Coroutine API contract

Public asynchronous I/O uses C++ coroutines. Core public names live in
`eventloop`, HTTP names in `eventloop::http`, and WebSocket names in
`eventloop::ws`. Platform readiness machinery is an internal implementation
detail; applications register the library's TCP, TLS, and UDP objects with
`eventloop::event_loop`, then await their operations. `post()` and executor
submissions remain bounded command and background-work APIs.

QUIC endpoints reserve 80 active stream slots per connection: 32 bidirectional
and 8 unidirectional streams for each initiator. Requested advertised counts
are capped to those peer reservations; local opens obey the peer's cumulative
grant and the separate local active reservation. A stream releases its slot
after both directions complete and sent data is acknowledged. Retired peer
streams replenish `MAX_STREAMS` credit. Retired IDs are kept in bounded
ordinal ranges so delayed packets cannot reopen them; pathological sparse
retirement can exhaust that range storage and delay further reclamation.
The aggregate receive-data window remains at most 128 KiB, independently
of stream count, with at most 4 KiB buffered per stream. No stream storage falls
back to an unbounded allocation.

`quic_connection::reset_stream()` and `stop_sending()` take an application
error code up to 2^62-1 and complete synchronously on the owner loop; the
frame is queued in the stream's fixed slot and retransmitted until
acknowledged. A reset discards queued bytes that were not yet sent, and later
writes fail with `quic_errc::stream_reset`; a peer STOP_SENDING has the same
effect. After `stop_sending()`, buffered and later data are discarded and the
peer's RESET_STREAM is consumed internally, so the stream retires without
further reads; reads fail with `quic_errc::invalid_state`. Both operations
leave an already finished direction unchanged, return
`quic_errc::invalid_argument` for an unknown stream or the missing direction of
a unidirectional stream, and return `quic_errc::not_connected` once the
connection is closing. A write to a stream that has already retired returns
`quic_errc::invalid_argument`. Every local close sends one CONNECTION_CLOSE
at the highest encryption level with keys: `close()` and `quic_endpoint::close()`
send transport `NO_ERROR`, `close_application()` sends its code (as
`APPLICATION_ERROR` before 1-RTT keys exist), and a local protocol failure
sends the RFC 9000 code (`PROTOCOL_VIOLATION` for stream and flow violations,
`CRYPTO_ERROR` with the TLS alert for handshake failures). Initial-level closes
are padded to 1200 bytes. The close is not retransmitted and no closing period
is kept, so a lost close leaves the peer to its idle timeout; a UDP failure or
event-loop cancellation sends none. Endpoint close keeps its socket open until
every running connection has sent its close and retired.

## TOML configuration parsing

- Include `eventloop/util/toml.h` and call
  `eventloop::util::parse_toml(input, nodes, decoded_strings)` for synchronous
  parsing of [TOML 1.1.0](https://toml.io/en/v1.1.0). The result is
  `std::expected<toml_document, toml_error>`. This utility has no loop affinity,
  asynchronous work, or cancellation operation and is available on Linux,
  macOS, and Windows. Applications handle file reading separately.
- The parser borrows the input `std::string_view`, a mutable
  `std::span<toml_value>`, and a mutable `std::span<char>` for decoded strings.
  Keep all three backing buffers alive and unchanged while using the document
  or any node, key, or string view obtained from it. The document is a view;
  copying it does not copy or own the parsed data. Parsing into the same
  storage again invalidates earlier documents and views.
- The caller sets node and decoded-string capacities through the spans.
  The root consumes one node, as does each value or implicit table. Keys and
  plain strings may borrow the input; escaped strings and strings requiring
  newline normalization consume decoded storage. `node_capacity` and
  `string_capacity` report exhaustion without growing storage. Nested values
  and dotted paths have a maximum depth of 64; exceeding it reports
  `nesting_limit`. The document reports `nodes_used()` and `strings_used()`.
- Parse errors carry a `toml_error_code` and a byte offset into the input.
  Invalid UTF-8, duplicate keys, conflicting table definitions, invalid values,
  and capacity limits return an error. Failure may partially overwrite the
  storage; no document is returned. Callers must inspect the result before
  accessing data.
- `root()` is the unnamed table. Use `toml_value::find(name)` to look up one
  decoded key component, `at(index)` to select an array element, and range
  iteration to visit children in source order. `find("a.b")` names a single
  key; traverse `find("a")` then `find("b")` for a dotted path. Lookup and
  indexing scan siblings. Check `type` before reading the associated value
  field; applications validate their own configuration schema and ranges.
- Integers use signed 64-bit storage; floats use `double`. Date and time values
  retain their TOML kind and local fields. Fractional seconds use nanoseconds,
  truncating additional precision; omitted seconds are zero. Offset date-time
  values retain the offset in minutes rather than converting to UTC.
  The parser uses caller storage and bounded local state. File I/O and setup
  libraries may allocate independently; this is not a process-wide allocation
  guarantee.

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
- On POSIX, an `event_loop` blocks SIGPIPE in the signal mask of the thread
  that constructs it, for as long as any loop lives on that thread. Socket
  writes that cannot pass `MSG_NOSIGNAL`, such as OpenSSL's kernel-TLS
  `write()` and `sendfile()`, then fail with EPIPE instead of ending the
  process when a peer disconnects. The last loop on the thread discards a
  pending SIGPIPE and unblocks it again. Other threads' masks and the
  process-wide disposition are unchanged.

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

## Unix domain stream sockets (Linux and macOS)

- Include `eventloop/unix_socket.h` for filesystem-path `unix_acceptor` and
  `unix_stream`. Windows does not build this API. Construct a listener with a
  path and a client stream with the same path; add each object to its owning
  loop before awaiting. Paths must be nonempty, contain no NUL byte, and fit
  in the platform's `sockaddr_un::sun_path` with a trailing NUL. Invalid paths
  throw `std::invalid_argument` at construction. Abstract namespace addresses
  are not supported.
- `unix_acceptor::async_accept()` returns an owned `unique_fd`, which can be
  passed to `unix_stream`. `unix_stream::async_connect()`, `async_read_some()`,
  and `async_write_some()` use the TCP stream result and cancellation rules.
  The client path is copied at construction. Caller-owned read and write
  buffers remain valid until completion. One accept, one connect, one read,
  and one write may be pending per object; duplicate and cancelled operations
  use the same errors as their TCP counterparts. Awaiter state lives in the
  caller's bounded coroutine frame.
- Binding never removes an existing path, including a stale socket path;
  bind reports the system error. `close()` and listener destruction remove the
  path only when it still names that listener's socket, so replacing the path
  does not cause the listener to delete the replacement. The listener owns the
  socket descriptor; accepted and client streams own theirs.

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
  Construction preallocates OpenSSL's read and write record buffers and throws
  `std::bad_alloc` if that allocation fails. The stream retains drained record
  buffers; OpenSSL may still allocate for other TLS processing.
- On Linux, `tls_stream::kernel_sendfile_available()` reports whether the
  completed handshake enabled OpenSSL transmit kTLS for this connection.
  When true, `tls_stream::async_send_file(file, offset, size)` owns the file
  descriptor through completion and sends that range as encrypted TLS data
  using `SSL_sendfile()`. It shares the one-write limit and returns `EBUSY`
  for a concurrent write, `EOVERFLOW` for an unrepresentable file range, and
  `EOPNOTSUPP` when transmit kTLS is unavailable. Cancellation and transport
  errors close the stream once sending has begun. On other platforms this
  operation returns `EOPNOTSUPP`. The overload taking a native descriptor
  borrows the file without duplicating or closing it; callers must keep it open
  until completion, including after requesting cancellation. It has the same
  error, cancellation, and one-write rules as the owning overload. Its optional
  prefix span is sent before the file range under the same write operation;
  callers must keep the prefix storage valid and unchanged until completion.
  HTTPS HTTP/1.1 file responses use this path
  when available and otherwise use a bounded 4 KiB read/write buffer.

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
- `http::server(loop, endpoint, options)`,
  `http::https_server(loop, endpoint, context, options)`, and
  `http::http3_server(loop, endpoint, certificate_chain, private_key, options)`
  take one `http::server_options`, and `http::redirect_server(loop, endpoint,
  hostname, https_port)` answers every request with 308. Options need `routes`,
  a `document_root`, or both; neither throws `std::invalid_argument`. Requests
  that match no route serve static files from `document_root`, or answer 404
  without one. The parser, the HTTP/1.1 session, and directory-listing
  rendering are private.
- HTTP accept loops spawn connection tasks. Each task owns its session and I/O
  buffers while suspended; accepted connections share ownership of the
  document-root descriptor and the router with the listener. Small file reads and metadata
  calls remain synchronous; large plain HTTP files use `sendfile`. Preserve
  the component-by-component `O_NOFOLLOW` path walk.
- Include `eventloop/http/router.h` to route requests to handlers. Routing
  runs on HTTP/1.1 (`http::server`, and `https_server` connections that
  negotiate `http/1.1`), on HTTP/2 (`https_server` connections that negotiate
  `h2`), and on HTTP/3 (`http3_server`, for `https` requests).
  - A `http::router` holds up to 64 routes (`max_routes`) and is built before
    a server takes it as `std::shared_ptr<const router>`.
    - `add(method, path, handler, context)` matches a path exactly, and
      `add_prefix` matches any path starting with the prefix. Paths start with
      `/` and contain no `?` or `#`. Matching uses the raw path before `?`,
      without percent-decoding.
    - Among routes matching the path, an exact route beats a prefix, and a
      longer prefix beats a shorter one.
    - HEAD without a HEAD route runs a GET route; the response keeps its
      status and fields, and body writes are discarded.
    - OPTIONS without an OPTIONS route answers 204 with `Allow`. A path routed
      only for other methods answers 405 with `Allow`.
    - Registration returns `file_exists` for a duplicate method and path,
      `invalid_argument` for a bad path or null handler, and
      `no_buffer_space` past 64 routes. It copies the path, so it may
      allocate; matching does not.
  - A handler is a free coroutine function
    `task<void>(event_loop&, http::request&, http::response&)`. Coroutine
    lambdas do not work, because frame allocation needs the loop as the first
    argument. Its frame comes from the loop's bounded size classes: with the
    default capacities it should fit the 1024-byte class (10240 slots),
    because larger classes hold only a few frames. A frame that cannot be
    allocated answers 503. The route's `context` pointer is returned by
    `request::route_context()` and must outlive every server using the router.
  - `http::request` views the method, path, query, authority, fields, and
    Content-Length until the handler completes; `header_value` compares names
    case-insensitively. `async_read_body(buffer)` reads up to `buffer.size()`
    body bytes and returns 0 at the end. One read may be pending; another
    returns `operation_in_progress`. Connection loss or a peer reset returns
    `connection_reset`. A request declaring more than
    `server_options::max_request_body` (default 1 MiB) answers 413 without
    running the handler.
    - HTTP/1.1 bodies use Content-Length or `Transfer-Encoding: chunked`.
      Chunk extensions are skipped and request trailers are checked for a
      name and colon, then dropped. Chunk-size lines are limited to 1 KiB
      and the trailer section to 8 KiB. A malformed chunked body returns
      `bad_message` and answers 400 if the handler returns without a
      response. A read past `max_request_body` returns `message_size` and
      answers 413 the same way. Either one closes the connection.
      Content-Length together with chunked answers 400; other transfer
      codings, and chunked bodies on static requests, answer 501. A chunked
      body on a routed path without a handler for the method gets its 204 or
      405 and the connection closes. The first body read answers
      `Expect: 100-continue` with 100 Continue.
    - HTTP/3 bodies may omit Content-Length. A read past
      `max_request_body` returns `message_size`, and the server answers 413
      if the handler then returns without a response. A malformed body
      (DATA beyond Content-Length, a truncated frame, invalid trailers)
      returns `bad_message` and resets the stream with the RFC 9114 code.
      Request trailers are validated but not exposed.
    - HTTP/2 bodies may omit Content-Length and follow the same 413 rule as
      HTTP/3. A malformed body (DATA beyond Content-Length, or a body shorter
      than it at END_STREAM) resets the stream with PROTOCOL_ERROR, and reads
      return `connection_reset`. Request trailers are validated but not
      exposed.
  - `http::response` sends the status and fields with `async_start`, body
    bytes with `async_write`, and the end with `async_finish(trailers)`.
    `async_send` does all three with content-length set, and `async_send_file`
    sends a file range it owns through completion. Spans are borrowed until
    each operation completes, and one operation may be pending at a time.
    - Field names must be lowercase tokens, and connection-specific fields and
      statuses outside 200..599 are `invalid_argument`. The server adds `date`
      when absent.
    - A declared content-length is enforced: writing past it is
      `invalid_argument`, and finishing short is `invalid_argument` and
      abandons the response. Without content-length, HTTP/1.1 uses chunked
      transfer coding, and HTTP/2 and HTTP/3 end the stream. On HTTP/1.1,
      trailers are sent only on chunked responses to requests with
      `TE: trailers`; HTTP/2 and HTTP/3 always send them. Status 204 and 304 carry no body. HTTP/3 response
      sections and trailers are limited to 61 and 64 fields; more is
      `message_size`.
    - A handler that returns before `async_start` gets a 500 response. One that
      returns after `async_start` but before `async_finish` closes the
      HTTP/1.1 connection, resets the HTTP/2 stream with INTERNAL_ERROR, or
      resets the HTTP/3 stream with `H3_INTERNAL_ERROR`.
    - An unread HTTP/1.1 request body is discarded before the next request on
      the connection, except after `Expect: 100-continue` without a read,
      which closes the connection. An unread HTTP/2 body is ended with
      RST_STREAM NO_ERROR after the response (RFC 9113 8.1), and an unread
      HTTP/3 body with STOP_SENDING `H3_NO_ERROR` (RFC 9114 4.1).
  - HTTP/1.1 runs one handler at a time per connection. Routing state, a 4 KiB
    response buffer, and the request view are allocated once per connection
    when the server has routes.
  - HTTP/2 runs one handler task per stream, up to 32 per connection, next to
    a reader task and the connection task, which writes. A handler's
    `async_write` completes once its bytes enter the connection's 256 KiB
    output queue under flow control and RFC 9218 priority; `async_send_file`
    completes once the last range is queued. Each connection allocates its
    session, 32 handler slots, and their request views once.
    - Routed uploads use a pool of eight 16 KiB stream buffers, allocated the
      first time a routed request with a body arrives. With routes, the
      server advertises a 16 KiB initial stream window and returns credit as
      handlers read. An upload arriving while all eight buffers are busy is
      refused with RST_STREAM REFUSED_STREAM, which clients may retry.
    - A client may send up to the default 64 KiB window before it applies
      that SETTINGS. A DATA frame that does not fit its stream buffer pauses
      reading the connection until the handler reads, so other streams wait
      meanwhile; a handler that never reads is ended when it responds.
    - Cancelling a handler task, for example with `with_timeout` around
      `async_read_body`, resumes a waiting read or write with
      `operation_canceled`. A cancelled write or file send also resets the
      stream with CANCEL, so the connection stops borrowing its data.
      Connection loss resumes every waiting handler with `connection_reset`,
      and the connection waits for all handlers before it is released.
  - HTTP/3 runs a handler inside each request's existing coroutine, using
    that request's scratch buffer. Request concurrency and refusal follow the
    `http3_server` request capacity below.
  - Steady-state routed requests make no general-heap allocation on a
    kept-alive HTTP/1.1 connection, on an HTTP/2 connection (TLS included),
    or on an HTTP/3 connection (QUIC included). Static HTTP/2 and HTTP/3 file
    requests make none either. HTTP/2 decodes request fields into the
    connection's existing strings, keeps its HPACK dynamic table in one
    4 KiB ring allocated with the first entry, and encodes response fields
    from views into one reused buffer, so only a header value longer than
    earlier ones on the connection can still allocate.
    `tests/http_routing_allocations.cc`,
    `tests/http2_routing_allocations.cc`, and
    `tests/http3_routing_allocations.cc` check these paths. The HTTP/2 and
    HTTP/3 tests also count OpenSSL's own allocations through its allocator
    hook, and those are zero per request too. TLS and QUIC handshakes do
    allocate inside OpenSSL, for key exchange, transcript hashing, and the key
    schedule, on every new connection. QUIC packet-protection keys are derived
    with one per-thread HMAC-SHA256 context instead of an OpenSSL KDF context
    per derivation.
- `eventloop::http::https_server` advertises `h2` and `http/1.1` with ALPN by
  default. Set `eventloop::http::server_options::enable_http2` to `false` to
  disable HTTP/2. The
  HTTP/2 path serves static GET, HEAD, and OPTIONS over TLS and routed
  requests as described above, supports up to 32 active streams per
  connection, decodes bounded HPACK header blocks, and observes connection and
  stream DATA flow control. Static request bodies are discarded and limited to
  1 MiB. File responses stream from their owned descriptors; inline
  response bodies are bounded to 4 MiB per connection. Responses are scheduled
  by RFC 9218 priority, taken from the request `priority` field and replaced
  by PRIORITY_UPDATE frames. Lower urgency goes first. Within one urgency,
  non-incremental responses are sent one at a time in stream order, then
  incremental responses share DATA frames round-robin. A stream blocked by flow
  control does not hold back others. Requests without a signal use urgency 3,
  non-incremental. A malformed Priority value keeps the defaults, and an update
  for a stream that is not open is ignored. The server advertises
  SETTINGS_NO_RFC7540_PRIORITIES and ignores RFC 7540 PRIORITY frames apart
  from their validity checks. On Linux, file response
  DATA uses OpenSSL `SSL_sendfile()` when transmit kTLS is active, and otherwise
  uses the bounded buffered path. Directory-root traversal shares HTTP/1.1's
  component-by-component `O_NOFOLLOW` checks. Cleartext
  prior-knowledge HTTP/2, h2c upgrade, CONNECT tunnels, and extended CONNECT are
  not supported. Plain `http::server` continues to serve HTTP/1.1.
- Built-in static-file GET and HEAD responses over HTTP/1.1, HTTP/2, and
  HTTP/3 include a weak metadata ETag, Last-Modified, and
  `Accept-Ranges: bytes`. `If-None-Match` takes precedence over
  `If-Modified-Since`; a matching validator returns 304 with no body.
  `If-Modified-Since` accepts the emitted IMF-fixdate form. A single valid
  `bytes` range (closed, open-ended, or suffix) returns 206 with
  `Content-Range`; an unsatisfiable single range returns 416 with
  `Content-Range: bytes */<full-size>` and no body. Malformed or multiple
  ranges are ignored and receive the full 200 response. Range evaluation
  follows conditional evaluation. HEAD returns the GET status and headers
  without a body. Directory listings and redirects are unaffected. The
  weak ETag uses file size, nanosecond modification and change timestamps,
  and file identity where available. This catches ordinary same-size writes
  even if the modification time is restored. It is not a content digest;
  filesystems with coarse or synthetic change timestamps can still produce
  the same validator for different bytes.
- Built-in directory listings list a directory's own children except `.` and
  `..`, including hidden (dot) names, in stable byte-wise name order. Link text
  is HTML-escaped and `href` values are percent-encoded; directories get a
  trailing `/`. A directory with a regular `index.html` serves that file
  instead. Listings are bounded to 4096 entries and 1 MiB of generated HTML;
  exceeding either returns 500 with a short plain-text body. HTTP/1.1 and
  HTTP/2 and HTTP/3 list when `server_options::directory_listing` is set. The
  component-by-component `O_NOFOLLOW` document-root walk is unchanged.
- Include `eventloop/http2/client.h` for one outbound HTTPS HTTP/2 request.
  `http2::async_request(loop, endpoint, context, hostname, request)` owns the
  TLS socket from connect through close. `hostname` is used for certificate
  verification, SNI, and the default `:authority`; `endpoint` is a numeric
  address, so name resolution belongs to the caller. ALPN must select `h2`.
  Requests own their method, target, authority override, header strings, and
  body bytes or a `request_body_source` callback. Any valid HTTP method token
  is accepted, including GET, HEAD, POST, PUT, PATCH, DELETE, and OPTIONS.
  CONNECT returns `operation_not_supported` because a tunnel does not fit one
  buffered exchange.
  The owned body is limited to 4 MiB; a source can produce up to 1 TiB in
  chunks of at most 16 KiB. Set either the owned body or the source. The source
  is task-owned and called on the loop thread with a writable borrowed span;
  it returns 0 for EOF, a byte count within the span, or an operation error.
  Resources captured by the source must remain valid through completion,
  including cancellation. `Content-Length` is optional and can be supplied as
  a request header when known; it must be decimal and equal the owned body
  size or the source's total. A mismatch reports `invalid_argument`, before
  connecting for an owned body, or when a source exceeds the value or ends
  short of it. Connection-specific request fields and TE other than
  `trailers` are also `invalid_argument`. DATA transmission observes the peer's connection
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
  Responses are malformed, reporting `protocol_error`, when they carry
  connection-specific fields or any TE field, a non-numeric or
  conflicting Content-Length, DATA whose total differs from Content-Length,
  or any DATA content after a HEAD request or with status 204 or 304.
  Content-Length on those bodyless responses is not compared.
  RST_STREAM on the request stream returns `connection_reset`. A GOAWAY
  whose last stream ID is zero returns `connection_reset` because the request
  was not processed; otherwise the response continues to completion.
  A malformed RST_STREAM or GOAWAY frame is `protocol_error`.
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
  `h3`, a certificate/key pair, and an owned document-root descriptor when
  `document_root` is set. Its
  `run()` task accepts connections; `close()` stops acceptance and
  `async_close()` waits for endpoint retirement. Keep the server and its
  observed `run()` task alive until both operations complete. Routed
  requests run their handlers as described above; other GET, HEAD, and
  OPTIONS requests serve static files or `index.html` using the shared secure
  resource walk. Request header blocks are capped at 16 KiB and 128 fields, dynamic
  QPACK tables are disabled, and QUIC caps each connection at 32 peer
  simultaneously active bidirectional and eight peer unidirectional streams.
  The server has eight
  concurrent connection slots by default; `server_options::connection_capacity`
  accepts 1 to 256. Endpoint routing, connection state,
  waiters, and HTTP/3 task handles are allocated at construction in proportion
  to that capacity. Connections beyond it are rejected. Each connection has
  storage for 40 concurrent stream tasks. Completed task slots are reused.
  `server_options::request_capacity` reserves reusable request scratch
  buffers at startup; zero selects four per connection, and explicit values
  from 1 to 8192 are accepted. A request arriving while every buffer is in
  use, or whose coroutine frame cannot be allocated, is refused with
  `H3_REQUEST_REJECTED` on its stream; the connection continues. A buffer is
  held until the request stream ends, the server stops reading it, or it
  fails.
  `server_options::max_udp_payload_size` bounds application datagrams
  to 1200..8192 bytes and is negotiated down to the peer's advertised limit;
  handshake packets remain at 1200 so anti-amplification is unaffected. It
  defaults to 1472 (the standard Ethernet payload) because path MTU discovery
  is not implemented; constrained paths may lower it.
  Each scratch buffer is about 52 KiB. Ordinary static-file responses use that
  storage for HTTP/3 headers and I/O; directory listing still allocates its
  bounded entry and output vectors, and OpenSSL may allocate separately.
  Each active request holds one
  coroutine frame from the loop's 2048-byte size class, so callers should size
  `eventloop::event_loop_options::coroutine_frame_capacities` for the expected
  request concurrency; the shipped HTTP/3 examples scale those frame caps with
  the configured capacity. A frame-allocation
  failure rejects only the affected connection instead of stopping the
  listener; one for a peer unidirectional stream closes that connection with
  `H3_INTERNAL_ERROR`.
  Each peer unidirectional stream is parsed by type with about 300 bytes of
  fixed state in its reader frame; nothing is buffered beyond one partial
  integer. A client push stream, or a second control, QPACK encoder, or QPACK
  decoder stream, is `H3_STREAM_CREATION_ERROR`; FIN or reset of any of those
  three is `H3_CLOSED_CRITICAL_STREAM`. The control stream must begin with
  SETTINGS (`H3_MISSING_SETTINGS`); a second SETTINGS or a DATA, HEADERS,
  PUSH_PROMISE, or reserved HTTP/2 frame is `H3_FRAME_UNEXPECTED`. SETTINGS
  accepts at most 32 distinct identifiers (`H3_EXCESSIVE_LOAD` beyond that)
  and rejects duplicate or HTTP/2-only identifiers, and
  `ENABLE_CONNECT_PROTOCOL` or `H3_DATAGRAM` values above 1
  (`H3_SETTINGS_ERROR`).
  GOAWAY, MAX_PUSH_ID, and CANCEL_PUSH must hold exactly one push ID
  (`H3_FRAME_ERROR`); an increasing GOAWAY, decreasing MAX_PUSH_ID, or
  CANCEL_PUSH above the client's MAX_PUSH_ID is `H3_ID_ERROR`. Unknown frames
  are skipped by length. Because the server advertises a zero-capacity
  dynamic table, the encoder stream accepts only Set Dynamic Table Capacity 0
  (`QPACK_ENCODER_STREAM_ERROR`), and the decoder stream accepts only Stream
  Cancellation (`QPACK_DECODER_STREAM_ERROR`). Unknown stream types are
  refused with STOP_SENDING `H3_STREAM_CREATION_ERROR`. Each violation closes the connection with that code in
  CONNECTION_CLOSE, as does a client whose stream limit leaves no room for the
  server's three unidirectional streams (`H3_GENERAL_PROTOCOL_ERROR`). A
  connection that ends normally is closed with `H3_NO_ERROR`.
  Request streams are parsed as HTTP/3 frames: HEADERS, then DATA, then at
  most one trailing HEADERS, with unknown and reserved extension frames
  skipped by length anywhere. DATA before the request HEADERS, a frame after
  trailers, or a control, PUSH_PROMISE, or reserved HTTP/2 frame is
  `H3_FRAME_UNEXPECTED`; a FIN inside a frame is `H3_FRAME_ERROR`; a QPACK
  section that uses the dynamic table or does not decode is
  `QPACK_DECOMPRESSION_FAILED`. Those close the connection. Errors confined to
  one request reset the response and send STOP_SENDING with the same code,
  and the connection continues. A malformed request is `H3_MESSAGE_ERROR`:
  missing, duplicate, unknown, or late pseudo-header fields (including
  `:protocol`), an empty `:path` or missing authority for `http`/`https`,
  `:authority` and Host that disagree, uppercase or invalid field names,
  NUL, CR, LF, or DEL in values, connection-specific fields, TE other than
  `trailers`, a non-numeric or conflicting Content-Length, DATA whose total
  differs from Content-Length, or a pseudo-header in trailers. A stream
  ending before its request HEADERS is `H3_REQUEST_INCOMPLETE`. A field
  section above the 16 KiB header cap or the decode limits, or If-None-Match
  values that do not fit request storage, is `H3_EXCESSIVE_LOAD`. A file read
  failure is `H3_INTERNAL_ERROR`, and a response write that fails because the
  peer stopped or reset the stream is `H3_REQUEST_CANCELLED`. CONNECT is
  answered 405 and a `:scheme` other than `https` 400. The response is sent
  once the request HEADERS are valid. The server then reads the rest of the
  request: DATA is counted and dropped, and trailers are decoded into the
  request's own storage. Violations found after the response reset a stream
  whose response may already be complete. After 1 MiB of request DATA the
  server stops reading with STOP_SENDING `H3_NO_ERROR` (RFC 9114 4.1), so
  Content-Length is not checked past that point. Request bodies are not
  delivered to handlers. Directory listings are available when the server is
  constructed with `directory_listing` and follow the shared bounded
  renderer. HTTP/3 server push and WebTransport are not supported.
