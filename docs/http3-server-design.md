# HTTP/3 server API design

The public caller constructs `http::http3_server` with an event loop, UDP
address/port, document root, certificate chain and private key, then spawns
`run()`. The server owns its QUIC endpoint and a shared root descriptor.
The endpoint owns its UDP socket and accepted connection slots. Every request
task owns its accepted stream ID and borrows the connection while its parent
session remains alive. All work and cancellation run on the owning loop.

The initial application scope is GET, HEAD and OPTIONS on static files and
`index.html`; unsupported methods receive 405. Paths use the existing secure
`open_resource` component walk. Directory listings and request bodies are
excluded initially. HTTP/3 uses ALPN `h3` and QUIC v1/v2 through the existing
public endpoint. A connection admits at most 32 peer bidirectional streams
and eight peer unidirectional streams; request header blocks are capped at
16 KiB and 128 fields. QPACK dynamic tables are disabled. File DATA is
streamed in fixed chunks. Exceeding advertised QUIC or HTTP/3 capacity
terminates the affected request or connection with an explicit error.

At most eight connections are active at once, matching the endpoint's fixed
slot count. Peer SETTINGS payloads are capped at 1 KiB. A request HEADERS
frame above 16 KiB closes that connection; accepted streams beyond the fixed
40 stream slots close it as well. The current implementation validates the
first peer SETTINGS frame and drains later control-stream bytes without
interpreting them.

`run()` stops when endpoint acceptance ends; `async_close()` closes QUIC and
waits for endpoint tasks to retire. Root and connection state stay alive until
their tasks finish. This API targets the platforms already supported by the
public QUIC endpoint and HTTP resource implementation: Linux, macOS, and
Windows with TLS enabled.
