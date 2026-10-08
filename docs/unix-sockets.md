# Unix domain stream socket API contract

Shared results, ownership, affinity, and cancellation: [coroutines](coroutines.md).

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
