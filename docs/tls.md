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
- On Linux a server handshake starts when the ClientHello is readable, not
  inline after accept, so its CPU-heavy first flight queues behind sockets
  that were already ready.
- A `tls_context` is immutable once created (session cache and tickets are
  off), so streams on different loops and threads may share one.
- Contexts require TLS 1.2 or later. TLS 1.2 offers only ECDHE/DHE suites
  with AES-GCM or ChaCha20-Poly1305, so no suite RFC 9113 prohibits for
  HTTP/2 is negotiated.
- A write covers at most three 16 KiB records (48 KiB), also through the
  gathered `async_write_some(span<const span<const byte>>)`, and completes
  once all of them are sent. Smaller buffers each still become a record.
- OpenSSL allocates a read or write record buffer (about 16.5 KiB each) while
  a record is in flight and frees it once drained, so an idle stream holds
  none. A failed allocation fails the operation with `ENOMEM` and closes the
  stream. Other OpenSSL processing may allocate. Reads use read-ahead: one
  transport read takes as many application records as the record buffer holds.
- On Linux the stream keeps no buffers of its own; OpenSSL reads the socket
  directly. After a handshake without transmit kTLS, records are sent by the
  stream with `MSG_MORE` on all but the last of a write, so the kernel pushes
  them together.

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
the same write operation; what the socket takes at once goes out with
`MSG_MORE`, so the kernel puts it in the same record as the range's first bytes. All other rules match the owning overload. HTTPS
HTTP/1.1 file responses use kTLS when available, otherwise a 16 KiB buffer,
allocated only while the body is sent, so each write is one full record.
