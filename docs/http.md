# Shared HTTP API contract

This document covers server configuration, routing, request/response ownership,
and static resources shared by the HTTP protocols. Task results, loop affinity,
and cancellation follow the [coroutine and event-loop contract](coroutines.md).

Read the relevant protocol contract for framing, scheduling, capacities, and
protocol errors:

- [HTTP/1.1](http1.1.md): plain and TLS connections, chunked bodies, trailers,
  and connection reuse.
- [HTTP/2](http2.md): TLS negotiation, multiplexed streams, flow control,
  handler cancellation, and the outbound client.
- [HTTP/3](http3.md): QUIC server lifetime, request capacity, QPACK, and stream
  and connection errors.

## Servers and resource ownership

- `http::server(loop, endpoint, options)`,
  `http::https_server(loop, endpoint, context, options)`, and
  `http::http3_server(loop, endpoint, certificate_chain, private_key, options)`
  take one `http::server_options`, and `http::redirect_server(loop, endpoint,
  hostname, https_port)` answers every request with 308. Options need `routes`,
  a `document_root`, or both; neither throws `std::invalid_argument`. Requests
  that match no route serve static files from `document_root`, or answer 404
  without one. The parser, the HTTP/1.1 session, and directory-listing
  rendering are private.
- HTTP accept loops spawn connection tasks. Each task owns its session and I/O
  buffers while suspended; accepted connections share ownership of the
  document-root descriptor and the router with the listener. Small file reads
  and metadata calls remain synchronous; large plain HTTP files use `sendfile`. Preserve
  the component-by-component `O_NOFOLLOW` path walk.

## Routing

- Include `eventloop/http/router.h` to route requests to handlers. Routing
  runs on HTTP/1.1 (`http::server`, and `https_server` connections that
  negotiate `http/1.1`), on HTTP/2 (`https_server` connections that negotiate
  `h2`), and on HTTP/3 (`http3_server`, for `https` requests).
  - A `http::router` holds up to 64 routes (`max_routes`) and is built before
    a server takes it as `std::shared_ptr<const router>`.
    - `add(method, path, handler, context)` matches a path exactly, and
      `add_prefix` matches any path starting with the prefix. Paths start with
      `/` and contain no `?` or `#`. Matching uses the raw path before `?`,
      without percent-decoding.
    - Among routes matching the path, an exact route beats a prefix, and a
      longer prefix beats a shorter one.
    - HEAD without a HEAD route runs a GET route; the response keeps its
      status and fields, and body writes are discarded.
    - OPTIONS without an OPTIONS route answers 204 with `Allow`. A path routed
      only for other methods answers 405 with `Allow`.
    - Registration returns `file_exists` for a duplicate method and path,
      `invalid_argument` for a bad path or null handler, and
      `no_buffer_space` past 64 routes. It copies the path, so it may
      allocate; matching does not.
  - A handler is a free coroutine function
    `task<void>(event_loop&, http::request&, http::response&)`. Coroutine
    lambdas do not work, because frame allocation needs the loop as the first
    argument. Its frame comes from the loop's bounded size classes: with the
    default capacities it should fit the 1024-byte class (10240 slots),
    because larger classes hold only a few frames. A frame that cannot be
    allocated answers 503. The route's `context` pointer is returned by
    `request::route_context()` and must outlive every server using the router.

## Requests

- `http::request` views the method, path, query, authority, fields, and
  Content-Length until the handler completes; `header_value` compares names
  case-insensitively. `async_read_body(buffer)` reads up to `buffer.size()`
  body bytes and returns 0 at the end. One read may be pending; another
  returns `operation_in_progress`. Connection loss or a peer reset returns
  `connection_reset`. A request declaring more than
  `server_options::max_request_body` (default 1 MiB) answers 413 without
  running the handler.

Body framing, trailers, malformed-body errors, and unread-body cleanup are
defined in each protocol contract.

For HTTP/2 and HTTP/3, a CONNECT route can inspect
`request::connect_protocol()` and call `async_accept_websocket()` to return a
stream for `ws::web_socket`. Acceptance replaces ordinary response/body
operations for that exchange. The [WebSocket contract](websocket.md#routed-http2-and-http3-websockets)
specifies validation, bounded storage, ownership, and cancellation.
Authentication and Origin policy remain in the route handler.

## Responses

- `http::response` sends the status and fields with `async_start`, body
  bytes with `async_write`, and the end with `async_finish(trailers)`.
  `async_send` does all three with content-length set, and `async_send_file`
  sends a file range it owns through completion. Spans are borrowed until
  each operation completes, and one operation may be pending at a time.
  - Field names must be lowercase tokens, and connection-specific fields and
    statuses outside 200..599 are `invalid_argument`. The server adds `date`
    when absent.
  - A declared content-length is enforced: writing past it is
    `invalid_argument`, and finishing short is `invalid_argument` and
    abandons the response. Status 204 and 304 carry no body. Framing and
    trailer handling follow the protocol contract.
  - A handler that returns before `async_start` gets a 500 response. Returning
    after `async_start` but before `async_finish` abandons the response with
    the connection close or stream reset specified by the protocol contract.

## Static files and directory listings

- Built-in static-file GET and HEAD responses over HTTP/1.1, HTTP/2, and
  HTTP/3 include a weak metadata ETag, Last-Modified, and
  `Accept-Ranges: bytes`. `If-None-Match` takes precedence over
  `If-Modified-Since`; a matching validator returns 304 with no body and
  Content-Length equal to the full representation size.
  `If-Modified-Since` accepts the emitted IMF-fixdate form. A single valid
  `bytes` range (closed, open-ended, or suffix) returns 206 with
  `Content-Range`; an unsatisfiable single range returns 416 with
  `Content-Range: bytes */<full-size>` and no body. Malformed or multiple
  ranges are ignored and receive the full 200 response. Range evaluation
  follows conditional evaluation. HEAD returns the GET status and headers
  without a body. Directory listings and redirects are unaffected. The
  weak ETag uses file size, nanosecond modification and change timestamps,
  and file identity where available. This catches ordinary same-size writes
  even if the modification time is restored. It is not a content digest;
  filesystems with coarse or synthetic change timestamps can still produce
  the same validator for different bytes.
- Built-in directory listings list a directory's own children except `.` and
  `..`, including hidden (dot) names, in stable byte-wise name order. Link text
  is HTML-escaped and `href` values are percent-encoded; directories get a
  trailing `/`. A directory with a regular `index.html` serves that file
  instead. Listings are bounded to 4096 entries and 1 MiB of generated HTML;
  exceeding either returns 500 with a short plain-text body. All three
  protocols list when `server_options::directory_listing` is set. The
  component-by-component `O_NOFOLLOW` document-root walk is unchanged.
- `server_options::open_file_cache_capacity` (default 0, off; at most 65536)
  keeps up to that many regular files open per server, with their metadata,
  so repeated static requests skip opening, `fstat`, and closing the file.
  Entries are keyed by decoded path and are opened and checked only through
  the component-by-component `O_NOFOLLOW` walk. A hit at least one second
  after its last check walks the path again; a changed, replaced, or removed
  file, or one replaced by a symbolic link, then drops out or is reopened.
  Within that second the previous file and metadata are served: replace
  files atomically (write a new file, then rename it) so that a cached
  response stays consistent; an in-place edit can pair old metadata with new
  bytes. Each entry holds one file descriptor; storage is allocated when the
  server is constructed, and a hit makes no general-heap allocation. Entries
  in use by responses stay open until those responses finish; when every
  entry is in use, a request is served uncached. HTTP/1.1 bodies of 11 KiB or
  more are sent with `sendfile` from a duplicate of the cached descriptor.
  Directories, `index.html` lookups, and paths longer than 255 decoded bytes
  are not served from the cache. The cache belongs to the server's event loop.

## Allocation scope

Steady-state routed requests make no general-heap allocation on established
HTTP/1.1, HTTP/2 (TLS included), or HTTP/3 (QUIC included) connections in the
measured paths. Static HTTP/2 and HTTP/3 file requests make none either. See
each protocol contract for its allocation tests and exceptions, including
the HTTP/1.1 input-buffer allocation for request heads over 256 bytes. These are
per-request measurements: connection setup, TLS and QUIC handshakes, and bounded
directory-listing storage may allocate.
