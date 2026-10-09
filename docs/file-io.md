# File I/O API contract

Shared results, ownership, affinity, and cancellation: [coroutines](coroutines.md).

Include `eventloop/file_io.h` for `async_openat`, `async_read_at`, and
`async_write_at` in `eventloop`. Direct awaiters keep state in the caller's
frame; a dedicated bounded worker completes on the owning loop.

- `async_openat` returns an owning `unique_fd`. Its directory descriptor,
  read/write descriptors, and I/O buffers are borrowed through completion,
  including cancellation; do not close, reuse, or destroy them earlier.
- Open paths are copied into 256-byte awaiter storage: empty or >255-byte
  paths return `ENAMETOOLONG`, embedded NUL returns `EINVAL`. The caller's
  path view need not survive construction.
- Reads/writes use explicit offsets and may complete partially. Negative
  offsets, sizes above `INT_MAX`, or nonempty null buffers return `EINVAL`.
- `event_loop_options::file_io_depth` defaults to 128 and must be a power of
  two >= 2. Full operation/worker capacity returns `EAGAIN`; shutdown or
  cancellation returns `ECANCELED`. Cancellation still waits for worker
  retirement and can follow an already performed file operation.

A `preadv2(RWF_NOWAIT)` experiment was tested with Stonegate on 2026-10-09
(1/4/64 KiB static files) and dropped after showing no attributable serving gain.
Stonegate uses synchronous reads/sendfile and does not exercise `async_read_at`.
