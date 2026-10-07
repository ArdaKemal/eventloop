# TCP API contract

Task results, loop affinity, and cancellation follow the
[coroutine and event-loop contract](coroutines.md). Read that contract
together with the rules below.

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
- `eventloop::tcp_stream::async_send_file(header, file, offset, size)` takes
  ownership of its file descriptor and sends the optional header followed by
  `size` bytes from `offset`. It reads at that offset and leaves the file
  position unchanged. Plain HTTP uses it for larger files and byte ranges; preserve the component-by-component `O_NOFOLLOW` path walk that protects document-root access.

TLS operations are specified in the [TLS contract](tls.md). Unix domain
streams use these result and cancellation rules; see the
[Unix socket contract](unix-sockets.md) for their ownership and path rules.
