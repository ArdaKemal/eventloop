# TCP API contract

Shared results, ownership, affinity, and cancellation: [coroutines](coroutines.md).
Names below are in `eventloop`.

- Include `eventloop/tcp_acceptor.h` and `eventloop/tcp_stream.h`. Numeric
  IPv4/IPv6 addresses use `ip_endpoint`; IPv6 sockets are v6-only, and
  `parse()` accepts numeric scope IDs after `%`. Add objects to the loop
  before awaiting operations.
- `tcp_acceptor::async_accept()` returns an owning `unique_fd`.
  `tcp_stream::async_connect`, `async_read_some`, and `async_write_some`
  return expected results. Reads/writes may be partial; zero read means EOF.
  Borrowed buffers stay valid through completion, including cancellation.
- One read and one connect may be pending; writes and file sends share the
  write direction. Duplicate pending I/O returns `EBUSY`; a second pending connect returns
  `EALREADY`. Immediate connect failure leaves the stream registered for
  inspection/close; pending connect failure or cancellation removes it.
  Check results or saved descriptors before retaining a pointer after failure.
- `async_send_file(header, file, offset, size)` takes file ownership and sends
  the borrowed header followed by the range without moving the file position.
  Keep the header valid through completion. It returns
  `task<expected<void, error_code>>`, requiring a frame and both result layers.

See [TLS](tls.md) for encrypted operations and [Unix sockets](unix-sockets.md)
for TCP-compatible local streams. HTTP document-root security belongs to
[shared HTTP](http.md).
