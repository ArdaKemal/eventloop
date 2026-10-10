# Changelog

Notable changes per release. The version follows [Semantic Versioning](https://semver.org);
before 1.0, minor versions may change public APIs. The CMake package accepts
the same major version (`SameMajorVersion`).

## 0.1.0 (unreleased)

First versioned release.

### Runtime

- C++23 coroutine event loop on Linux (epoll), macOS (kqueue), and Windows
  (IOCP), with loop-affine I/O, cancellation, and resumption.
- Bounded per-loop coroutine frame classes up to 4 KiB with no heap fallback;
  bounded queues, worker pools, and file I/O with explicit exhaustion results.
- Task composition (`race`, `with_timeout`), timers, wakeups, bounded channels,
  semaphores, blocking-work and file I/O offload, and a TOML parser.

### Networking and protocols

- TCP, TLS (OpenSSL 3.5+, optional kTLS), Unix sockets, and UDP.
- QUIC v1/v2 endpoints with streams and DATAGRAMs.
- HTTP/1.1, HTTP/2 (server and single-request client), and HTTP/3 servers
  sharing routing and secure static-file serving.
- Bounded WebSocket framing over TCP/TLS streams and HTTP/2 or HTTP/3
  Extended CONNECT.

### Quality

- CI on Linux (gcc, clang), macOS, and Windows (MSVC). On Linux, the full
  suite also runs under ASan with UBSan and under TSan, and the protocol
  parsers are fuzzed.
- Windows fixes for IOCP cancellation and send completions, UDP sends, and
  an HTTP/3 request coroutine whose frame exceeded the largest frame class in
  MSVC Debug builds.
