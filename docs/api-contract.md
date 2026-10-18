# API contract index

Load only the affected topics. Async work also requires [coroutines](coroutines.md);
public API changes require [conventions](api-conventions.md). HTTP work requires
[shared HTTP](http.md) plus the affected protocol; add QUIC for HTTP/3 transport
changes. Contracts describe behavior; current test runs establish status.

| Topic | Defines |
| --- | --- |
| [Coroutines and event loop](coroutines.md) | Tasks/handles, results, frames, workers, cancellation, timers, wakeups, composition |
| [Bounded channel](channel.md) | Caller-owned slots, FIFO transfer, backpressure, close, cancellation |
| [Semaphore](semaphore.md) | Fixed permit capacity, move ownership, FIFO acquisition, cancellation |
| [File I/O](file-io.md) | Borrowed descriptors/buffers, path limits, worker capacity/completion |
| [TCP](tcp.md) | Numeric endpoints, owned sockets, partial I/O, connect failures, file sending |
| [TLS](tls.md) | TCP plus handshake, ALPN, close, concurrency, buffers, kTLS |
| [Unix sockets](unix-sockets.md) | FreeBSD/Linux/macOS paths, listener cleanup, TCP-compatible operations |
| [UDP](udp.md) | Atomic datagrams, truncation, concurrency |
| [QUIC](quic.md) | Stream reservations/windows, reset/stop-sending, connection retirement |
| [WebSocket](websocket.md) | Framing, payload views, send buffers, broadcast, routed Extended CONNECT |
| [Shared HTTP](http.md) | Options, routing, request/response ownership, static files, listings/cache |
| [HTTP/1.1](http1.1.md) | Plain/TLS servers, chunked bodies, trailers, reuse, allocations |
| [HTTP/2](http2.md) | ALPN, streams, flow control, priority, cancellation, closure history, client, allocations |
| [HTTP/3](http3.md) | Server lifetime/capacity, framing, QPACK, errors, client, allocations |
