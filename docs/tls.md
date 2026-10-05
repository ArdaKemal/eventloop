# TLS API contract

Task results, loop affinity, and cancellation follow the
[coroutine and event-loop contract](coroutines.md). Read that contract
together with the rules below.

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

Connection setup and inherited TCP operations follow the [TCP contract](tcp.md).
