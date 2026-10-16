# Shared HTTP API contract

Shared async rules: [coroutines](coroutines.md). Protocol-specific framing,
capacity, errors, and allocation tests: [HTTP/1.1](http1.1.md),
[HTTP/2](http2.md), [HTTP/3](http3.md). Names below are in `eventloop::http`.

## Servers and ownership

`server(loop, endpoint, options)`, `https_server(loop, endpoint, context,
options)`, and `http3_server(loop, endpoint, certificate_chain, private_key,
options)` use `server_options`. Supply `routes`, `document_root`, or both;
neither throws `std::invalid_argument`. Unmatched paths serve static resources,
or return 404 without a root. `redirect_server(loop, endpoint, hostname,
https_port, options)` returns 308 for every request and closes; it applies only
`reuse_port`, `header_timeout`, and `serving_loops` from `server_options`.

### Serving accepted connections on other loops

Where the application does not use shared-port listeners (macOS, FreeBSD,
Windows), one TCP listener can feed several loops. `server`, `https_server`,
and `redirect_server` hand accepted connections to the loops in
`server_options::serving_loops` in turn; empty means the listener's own loop,
which may also appear in the list. A connection for another loop is posted to
it with `event_loop::post()` and served entirely there. Each serving loop gets
its own document-root descriptor and open-file cache (the capacity applies per
serving loop); the router and TLS context are shared. A null entry throws
`std::invalid_argument`. If a loop's post queue is full the connection is
closed; if it is shutting down or out of frames, its spawn fails and closes the
connection. Every serving loop must outlive the listener's `run()` task.

Connection tasks own sessions/I/O buffers and share document-root/router
ownership with the listener. Small file reads/metadata calls are synchronous;
large plain HTTP files use sendfile. Static-file opens reject symlinks in every
path component. Linux uses `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`;
unavailable or blocked calls fall back to the component-by-component
`O_NOFOLLOW` walk. Other platforms retain their component walk. Parsers,
sessions, and listing renderers are private.

## Routing

Include `eventloop/http/router.h`. Routing works on plain/TLS HTTP/1.1,
TLS HTTP/2, and HTTPS HTTP/3. Build a router before passing it as
`shared_ptr<const router>`.

- `add(method, path, handler, context)` matches exactly; `add_prefix` matches
  path prefixes. Paths start with `/`, exclude `?`/`#`, and match the raw path
  before `?`, without percent decoding. Exact beats prefix; longer prefix wins.
- HEAD without a HEAD route runs GET, preserving status/fields and discarding
  body writes. OPTIONS without an OPTIONS route returns 204 with `Allow`.
  A path routed for other methods returns 405 with `Allow`.
- `max_routes` is 64. Registration copies paths and may allocate; matching
  does not. Errors: duplicate method/path `file_exists`, bad path/null handler
  `invalid_argument`, capacity `no_buffer_space`.
- Handlers are free coroutines `task<void>(event_loop&, request&, response&)`;
  coroutine lambdas cannot supply the required first loop argument for frame
  allocation. Fit the default 1024-byte class (10240 slots); larger classes
  have few slots. Frame exhaustion answers 503. `route_context()` returns the
  registration pointer; it must outlive every server using the router.

## Requests

Request method/path/query/authority/field/Content-Length views live until the
handler completes. `header_value()` compares names case-insensitively.
`async_read_body(buffer)` returns up to the span size, or zero at end. One
read may be pending; another returns `operation_in_progress`. Peer reset/loss
returns `connection_reset`. Declared bodies above `max_request_body` (default
1 MiB) answer 413 without running the handler. Framing, malformed bodies,
trailers, and unread-body cleanup are protocol-specific.

HTTP/2/3 CONNECT handlers can inspect `connect_protocol()` and call
`async_accept_websocket()`. Acceptance replaces ordinary body/response
operations; see [routed WebSockets](websocket.md#routed-http2-and-http3-websockets).
Authentication/Origin policy belongs to the handler.

HTTP/3 CONNECT routes can also call `async_accept_webtransport()` for negotiated
draft-16 (`webtransport-h3`) or browser draft-07 (`webtransport`) sessions when
`server_options::webtransport.enabled` is set. See [WebTransport](webtransport.md)
for admission, ownership, capacity, and flow-control differences.

## Responses

- `async_start` sends status/fields, `async_write` body bytes, and
  `async_finish(trailers)` the end. `async_send` performs all three with
  content-length; `async_send_file` owns the file range through completion.
  Spans are borrowed through each completion; one operation may be pending.
- Names must be lowercase tokens; connection-specific fields and statuses
  outside 200..599 return `invalid_argument`. Date is added when absent.
- Declared content-length is enforced: overrun returns `invalid_argument`;
  short finish does too and abandons the response. Status 204/304 has no body.
  Framing/trailers follow the protocol contract.
- Returning before start answers 500; returning after start without finish
  abandons the response (connection close or stream reset per protocol).

## Static resources

GET/HEAD file responses include weak metadata ETag, Last-Modified, and
`Accept-Ranges: bytes`. `If-None-Match` precedes `If-Modified-Since` (which
accepts emitted IMF-fixdate). Matches return 304, no body, and Content-Length
of the full representation. ETags use size, nanosecond mtime/ctime, and file
identity where available; ordinary same-size writes with restored mtime are
detected. They are not content digests: coarse/synthetic timestamps may collide.

Single closed/open-ended/suffix byte ranges return 206 with Content-Range;
unsatisfiable ranges return 416 with `bytes */<full-size>` and no body.
Malformed/multiple ranges receive full 200. Conditions precede range evaluation.
HEAD preserves GET status/headers without body. Listings/redirects are unaffected.

With a nonzero `advertise_http3_port`, `https_server` file responses (200,
206, 304, 416; HTTP/1.1 and HTTP/2) include `Alt-Svc: h3=":<port>"; ma=86400`.
Plain `server`, routed handlers, listings, errors, and redirects send none;
handlers add their own field. The caller runs the `http3_server` on that port.

With `directory_listing`, directories without regular `index.html` list their
children, including dot names but excluding `.`/`..`, in stable byte-wise name
order. Text is HTML-escaped, hrefs percent-encoded, directories suffixed `/`.
Limits: 4096 entries and 1 MiB HTML; overflow returns 500 with short plain text.
All protocols use the same renderer and secure traversal.

## Open-file cache

`open_file_cache_capacity` defaults to 0 (off), maximum 65536 regular files per
server/loop. Each entry owns a descriptor/metadata; startup allocates storage,
hits make no general-heap allocation. Decoded-path keys open/revalidate only
through the shared secure traversal. Hits within one second reuse file/metadata;
later hits reopen, replacing or dropping changed/replaced/removed files or
symlinks. Replace files atomically: in-place edits may pair old metadata with
new bytes during that interval.

In-use entries stay open through response completion; if all are busy, serve
uncached. Directories, index.html lookups, and decoded paths >255 bytes bypass
the cache. HTTP/1.1 sendfile bodies >=11 KiB duplicate cached descriptors for
ownership transfer. Shared cached descriptors require explicit-offset reads.

## Allocation scope

The protocol allocation tests check zero per-request allocations on warmed,
established routed connections and static HTTP/2/3 file paths, including
OpenSSL hooks for HTTP/2/3. Treat these as measured paths, not universal
allocation guarantees. Setup, handshakes, directory listings, and HTTP/1.1
request heads >256 bytes may allocate; see each protocol's exceptions/tests.
