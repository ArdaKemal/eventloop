# File I/O API contract

Task results, loop affinity, and cancellation follow the
[coroutine and event-loop contract](coroutines.md). Read that contract
together with the rules below.

- Include `eventloop/file_io.h` for `eventloop::async_openat`,
  `eventloop::async_read_at`, and `eventloop::async_write_at`.
  `eventloop::async_openat` returns an owning `eventloop::unique_fd` on success.
  Paths are copied into a bounded awaiter buffer. The directory descriptor
  passed to `async_openat` and file descriptors passed to `async_read_at` and
  `async_write_at` are borrowed; callers must keep them open and unreused until
  completion, including after cancellation. Read and write buffers remain
  caller-owned and valid for the same period. Operations run on a dedicated
  bounded worker; a full `file_io_depth` returns an error.
