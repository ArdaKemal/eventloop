# Request routing (design draft)

Status: steps 1 (HTTP/1.1) and 2 (HTTP/3) are implemented and their behavior
is in [api-contract.md](api-contract.md), which takes precedence over this
draft. Steps 3 (HTTP/2) and 4 remain. This file is removed when routing covers all three
protocols.

Changes from the reviewed draft, made during step 1:

- The types are split: `request` in `http/request.h`, `response` in
  `http/response.h`, `router` and `handler` in `http/router.h`, and
  `server_options` in `http/server_options.h`.
- `add_prefix` matches any path starting with the prefix, not only at a
  segment boundary. Register `/api/` to stop at a segment.
- HTTP/1.1 answers 413 from the declared Content-Length before the handler
  runs. Bodies need Content-Length; chunked requests stay 501.
- The server adds `date` when absent, but not `server`.
- Handler frames must fit the 1024-byte class with the default capacities;
  the 2048 class has four slots.
- HTTP/1.1 sends 100 Continue on the first body read for
  `Expect: 100-continue`. It closes the connection if the handler answers
  without reading that body.
- HTTP/1.1 still rejects methods outside `method_type` with 400.
- Connection tasks take a private slim copy of the options, because the full
  struct pushed the HTTP/1.1 connection frame past the 1024-byte class.

Changes made during step 2:

- HTTP/3 QPACK decoding does not allocate, so routed and static HTTP/3
  requests both measure zero heap allocations, QUIC stack included
  (`tests/http3_routing_allocations.cc`).
- The request frame parser now delivers DATA payloads as views of its input
  and can move trailer blocks to other storage after the request section is
  decoded.
- Each HTTP/3 request scratch buffer grows by 12 KiB, to about 52 KiB: a
  copy of the regular request fields as `http::header`, and 8 KiB for
  response HEADERS, trailers and file DATA. Request trailers use the free
  HEADERS buffer.
- HTTP/3 bodies may omit Content-Length. The body limit is then enforced on
  read (`message_size`, then 413 if the handler returns without a response).
  Request trailers are validated but not exposed to handlers.
- HTTP/3 response sections are limited to 61 caller fields and trailers to 64.
- Routing runs in its own coroutine. Inlined in the request coroutine, it
  pushed that frame from 1800 to 2208 bytes, past the 2048-byte class.

## Goals

- One routing API shared by HTTP/1.1, TLS HTTP/1.1 or HTTP/2, and HTTP/3.
  Handlers do not see which protocol carried the request unless they ask.
- Handlers are coroutine tasks that stream the request body in and the
  response body out.
- Routing adds no general-heap allocation per request. Per-request state lives
  in the handler's coroutine frame (from the loop's bounded size classes) and
  in protocol storage that already exists.
- The public HTTP surface gets smaller: parser and session internals leave the
  public headers, and all three servers take the same options.

## Public caller

Stonegate gains a `/healthz` route next to its static files. A new
`examples/routing_server.cc` shows exact and prefix routes, a streamed upload
that echoes its byte count, and a streamed response. Integration tests drive
it over all three protocols using only public headers.

```cpp
auto upload(event_loop& loop, http::request& request, http::response& response)
    -> task<void>
{
    std::array<std::byte, 4096> chunk;
    std::uint64_t total = 0;
    for (;;) {
        auto read = co_await request.async_read_body(chunk);
        if (!read || !*read) co_return;          // cancelled or failed: just return
        if (**read == 0) break;                  // end of body
        total += **read;
    }
    std::array<char, 20> text;
    const auto end = std::to_chars(text.data(), text.data() + text.size(), total).ptr;
    const std::array<http::header, 1> fields {{{"content-type", "text/plain"}}};
    co_await response.async_send(200, fields,
        std::as_bytes(std::span(text.data(), end)));
}

http::router routes;
routes.add(http::method_type::post, "/upload", upload);
routes.add_prefix(http::method_type::get, "/api/", api);

http::https_server server(loop, endpoint, context,
    {.routes = std::make_shared<const http::router>(std::move(routes)),
     .document_root = "./public"});
```

## Types

All new names are in `eventloop/http/router.h`; `method_type` and `header`
stay in `eventloop/http/request.h`.

### `http::handler`

```cpp
using handler = task<void> (*)(event_loop&, request&, response&);
```

A free coroutine function, following the `event_loop&`-first convention that
coroutine frame allocation relies on. Coroutine lambdas are not supported for
the same reason. A route may carry a `void*` context that the handler reads
with `request.route_context()`. The pointed-to state must outlive every server
using the router.

### `http::router`

```cpp
class router {
public:
    static constexpr std::size_t max_routes = 64;
    auto add(method_type, std::string_view path, handler, void* context = nullptr)
        -> std::expected<void, std::error_code>;
    auto add_prefix(method_type, std::string_view prefix, handler, void* context = nullptr)
        -> std::expected<void, std::error_code>;
};
```

- Paths must start with `/` and contain no `?` or `#`. `add` matches the path
  exactly. `add_prefix` matches at a segment boundary: `/api/` matches
  `/api/` and `/api/x`, not `/apix`. The match runs on the raw path before
  `?`, with no percent-decoding.
- An exact match beats a prefix match, and the longest prefix wins.
- A duplicate method and path is `file_exists`. A bad path is
  `invalid_argument`. More than `max_routes` routes is `no_buffer_space`.
  `add` copies the path, so building a router may allocate. Routing a request
  does not.
- Servers hold `std::shared_ptr<const router>`. A router cannot change after a
  server takes it, and one router can be shared by several servers.

### Dispatch order

1. The path matches a route for the request method: run that handler.
2. HEAD with no HEAD route but a GET route: run the GET handler. The response
   keeps its status and headers, and body writes are discarded.
3. OPTIONS with no OPTIONS route on a matched path: 204 with `Allow`.
4. The path matches routes for other methods: 405 with `Allow`.
5. A `document_root` is set: the existing static-file behavior, unchanged.
6. Otherwise: 404.

Methods outside `method_type` (`unknown`) can only reach steps 4 to 6.

### `http::request`

This replaces the current parser output struct of the same name, which moves to
a private header.

```cpp
class request {
public:
    method_type method() const noexcept;
    std::string_view method_name() const noexcept;
    std::string_view path() const noexcept;       // before '?'
    std::string_view query() const noexcept;      // after '?', may be empty
    std::string_view authority() const noexcept;  // :authority or Host
    http::protocol protocol() const noexcept;     // http1_1, http2, http3
    std::span<const header> headers() const noexcept;
    std::optional<std::string_view> header_value(std::string_view name) const noexcept;
    std::optional<std::uint64_t> content_length() const noexcept;
    void* route_context() const noexcept;

    // Reads up to buffer.size() body bytes. 0 is end of body.
    task<std::expected<std::size_t, std::error_code>> async_read_body(std::span<std::byte>);
};
```

- Every view stays valid until the handler task completes. Header names
  compare case-insensitively, and HTTP/2 and HTTP/3 names are already
  lowercase.
- Body reads:
  - The buffer is borrowed until the read completes.
  - One read may be pending at a time; a second returns `operation_in_progress`.
  - A request body above `max_request_body` returns `message_size`, then the
    server answers 413 if the response has not started, or resets the
    stream.
  - A peer reset or connection loss returns `connection_reset`.

### `http::response`

```cpp
class response {
public:
    task<std::expected<void, std::error_code>> async_start(unsigned status,
        std::span<const header> headers);
    task<std::expected<void, std::error_code>> async_write(std::span<const std::byte>);
    task<std::expected<void, std::error_code>> async_finish(
        std::span<const header> trailers = {});
    // async_start + async_write + async_finish with Content-Length set.
    task<std::expected<void, std::error_code>> async_send(unsigned status,
        std::span<const header> headers, std::span<const std::byte> body = {});
    // Takes ownership of file; uses sendfile or kTLS where the static path does.
    task<std::expected<void, std::error_code>> async_send_file(unsigned status,
        std::span<const header> headers, unique_fd file, std::uint64_t offset,
        std::uint64_t size);
};
```

- **Starting:** status 100–199 and 101 are rejected with `invalid_argument`,
  as are invalid or connection-specific field names. The server adds `date`
  and `server` fields.
- **Writing:** each write's span is borrowed until the write completes. A write
  completes once the bytes are accepted into the protocol's bounded output, so
  slow peers apply backpressure. One write may be pending at a time.
- **Content-Length:** a declared Content-Length is enforced. Writing past it
  is `invalid_argument`, and finishing short resets the stream (closes the
  connection on HTTP/1.1). Without Content-Length, HTTP/1.1 uses chunked
  transfer coding, and HTTP/2 and HTTP/3 end the stream.
- **Trailers:** dropped on HTTP/1.1 unless the response is chunked and the
  request sent `TE: trailers`.
- **If the handler returns early:**
  - before `async_start`: the server sends 500;
  - after `async_start` but before `async_finish`: the stream is reset
    (HTTP/2 RST_STREAM INTERNAL_ERROR, HTTP/3 H3_INTERNAL_ERROR), and an
    HTTP/1.1 connection is closed;
  - with an unread request body: the server discards it. On HTTP/1.1 up to
    `max_request_body`, then the connection closes. On HTTP/2 an RST_STREAM
    NO_ERROR follows the response, and on HTTP/3 STOP_SENDING H3_NO_ERROR.

## Server options

One options struct replaces `server_options` and `http3_server`'s positional
arguments. Servers take an `ip_endpoint` instead of a port plus address
string.

```cpp
struct server_options {
    std::shared_ptr<const router> routes;
    std::filesystem::path document_root;     // empty: no static fallback
    bool directory_listing = false;
    bool reuse_port = false;                 // TCP servers
    bool enable_http2 = true;                // https_server
    std::size_t max_request_body = 1 << 20;  // per request, routed requests
    std::size_t connection_capacity = 8;     // http3_server
    std::size_t request_capacity = 0;        // http3_server, 0 = 4 per connection
    std::size_t max_udp_payload_size = 1472; // http3_server
};

server(event_loop&, ip_endpoint, server_options);
https_server(event_loop&, ip_endpoint, std::shared_ptr<tls_context>, server_options);
http3_server(event_loop&, ip_endpoint, std::filesystem::path certificate_chain,
             std::filesystem::path private_key, server_options);
redirect_server(event_loop&, ip_endpoint, std::string_view hostname, std::uint16_t https_port);
```

Options with neither `routes` nor `document_root` throw `std::invalid_argument`.

## Per-protocol execution

| | HTTP/1.1 | HTTP/2 | HTTP/3 |
|---|---|---|---|
| Handler tasks | One at a time per connection, awaited by the connection task | One per stream, spawned, at most 32 per connection | One per request stream, as today |
| Request body | Read from the socket through the session buffer; Content-Length only, chunked requests stay 501 | Per-stream 16 KiB buffer, advertised as the initial stream window; WINDOW_UPDATE as the handler consumes | QUIC stream flow control; DATA frames parsed into existing storage |
| Response body | Written straight to the socket | Copied into the existing 256 KiB output ring as DATA, under flow control and RFC 9218 priority | DATA frames written to the QUIC stream |
| Spawn failure | 503 | 503 | 503 (stream refused if headers cannot be sent) |

### HTTP/2 wake-up

The connection task and its handler tasks share one session on one loop.

- A private single-waiter awaiter (in `src/http2`, not public) lets a handler
  wait for body bytes or output room, and lets the connection task wait for
  socket input, handler output, or handler completion, whichever comes first.
- Handlers never touch the socket.
- The connection task keeps each handler's task handle and does not release
  the session until every handler has completed. This follows the "pending
  task is not cancelled by destroying its handle" rule.

## Capacity and allocation

Routing adds no general-heap allocation per request. Routed HTTP/1.1 and
HTTP/3 requests perform none (measured). HTTP/2 HPACK field decoding
allocates strings as it does today; reducing that is separate work. An
allocation-count test covers a routed GET and POST on each protocol.

| Bound | Value | When exhausted |
|---|---|---|
| Routes per router | 64 | `no_buffer_space` from `add` |
| Concurrent handlers | Coroutine size classes; frame and responder state must fit the 2048 class (measured) | 503 |
| HTTP/2 stream body buffer | 16 KiB × 32 streams, allocated with the session at connection start | Flow control holds the peer |
| HTTP/1.1 header block | 4096 bytes (`max_message_size`) | 431 |
| Request body | `max_request_body` | `message_size`, then 413 or reset |

## Cancellation and ownership

- `event_loop::shutdown()` and server close cancel handler tasks. Pending
  reads and writes return `operation_canceled`.
- A peer reset fails pending and later reads and writes with
  `connection_reset`. Handlers are expected to return.
- `async_send_file` owns its descriptor through completion, like
  `tcp_stream::async_send_file`.
- Wrong-loop use is a programming error.

## Public API removals

| Removed from public headers | Replacement |
|---|---|
| `http::session` (`http/session.h`) | Private `src/http/session.h`; `http_test.cc` includes it privately |
| `parse_request`, `parse_status`, `parse_result`, `max_headers`, `max_target_size` | Private parser header |
| `http/directory_listing.h` | Private; listings are reached through `directory_listing` |
| Port and address string constructors, `http3_server` positional arguments | `ip_endpoint` plus `server_options` |

`mime_type_from_path` stays public because handlers that send files need it.
Stonegate, Wayfarer, `tests/fixtures`, and the benchmark are updated in the
same change. The installed header list in CMake drops the removed headers.

## Implementation order

1. Router, the `request` and `response` types, options, and the constructor
   changes. HTTP/1.1 dispatch, then Stonegate `/healthz` and the example.
2. HTTP/3 dispatch, reusing the existing per-request coroutine.
3. HTTP/2: the wake-up awaiter, per-stream tasks, and streamed request and
   response bodies.
4. Allocation-count tests, the contract text, and removal of this file.

Each step is its own commit and leaves the full suite passing.

## Open points

- Should the handler signature be a plain function pointer plus `void*`
  context, as proposed, or should the router also accept member-function
  handlers bound to an object?
- Should 16 KiB per HTTP/2 stream for upload buffering be configurable? It
  caps upload throughput at about 16 KiB per round trip per stream.
- Should Stonegate's redirect mode stay a separate `redirect_server`, or
  become a router-only server with a single catch-all route?
