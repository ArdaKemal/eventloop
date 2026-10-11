# TLS API contract

Shared results, ownership, affinity, and cancellation: [coroutines](coroutines.md).
Setup/inherited operations: [TCP](tcp.md). Names below are in `eventloop`.

- `tls_stream` adds `async_handshake`, encrypted `async_read_some`/
  `async_write_some`, and `async_close`. Await `async_close()` to flush
  `close_notify`, then `close()` to retire the transport. `close()` immediately
  cancels/closes it; a loop-owned stream pointer is invalid after removal.
  A failed TLS operation closes the stream; a loop-owned stream removed that
  way is destroyed when its last pending TLS operation completes.
- One TLS read and write may coexist; duplicate directions return `EBUSY`.
  Handshake/async-close require other TLS operations idle. For outbound TLS,
  construct with an `ip_endpoint`, client context, and `tls_client_options`
  verification hostname (also SNI); `application_protocols` sets ALPN.
  Await inherited connect before handshake; unconnected handshake is `ENOTCONN`.
  Raw TCP send-file is hidden because it bypasses TLS framing.
- A `tls_context` is immutable once created (session cache and tickets are
  off), so streams on different loops and threads may share one.
- Construction preallocates OpenSSL read/write record buffers, throwing
  `std::bad_alloc` on failure, and retains drained buffers. Other OpenSSL
  processing may allocate.

## kTLS file sending

On Linux, `kernel_sendfile_available()` reports transmit kTLS after handshake.
`async_send_file(file, offset, size)` owns the file through completion and uses
`SSL_sendfile()` for encrypted data. It shares the one-write limit (`EBUSY`),
rejects unrepresentable ranges (`EOVERFLOW`), and returns `EOPNOTSUPP` without
transmit kTLS or on other platforms. Cancellation/transport errors close the
stream once sending begins.

The native-descriptor overload borrows without duplicating/closing the file;
keep it open through completion, including cancellation. Its optional prefix
span is borrowed unchanged for the same period and sent before the range under
the same write operation. All other rules match the owning overload. HTTPS
HTTP/1.1 file responses use kTLS when available, otherwise a bounded 4 KiB
read/write buffer.
