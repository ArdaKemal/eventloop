# HTTP/1.1 API contract

Shared async rules: [coroutines](coroutines.md). Routing, ownership, static
resources, listings/cache: [shared HTTP](http.md). Names are relative to `eventloop`.

## Connections and storage

`http::server` serves plain HTTP/1.1; `http::https_server` uses it when ALPN
selects http/1.1 and also advertises h2 by default. Disable h2 with
`http::server_options::enable_http2 = false`. One handler runs per connection.
Routed connections allocate routing state, request view, and 4 KiB response
buffer once. A body write that does not fit the buffer goes out in one
gathered write with the buffered head (and chunk framing), not after it.

## Bodies and reuse

- Content-Length or chunked request bodies are supported. Chunk extensions
  are skipped; trailers require name/colon then are discarded. Chunk-size
  lines <=1 KiB, trailer section <=8 KiB.
- Malformed chunked bodies return `bad_message`; overruns of `max_request_body`
  return `message_size`. If the handler returns without responding, answer
  400/413 respectively; either closes the connection.
- Content-Length plus chunked answers 400. Other transfer codings or chunked
  static bodies answer 501. Chunked routed paths without a method handler
  receive 204/405 then close. First body read sends 100 Continue for
  `Expect: 100-continue`.
- Discard unread bodies before reuse, except unread Expect: 100-continue,
  which closes the connection.
- Responses without content-length use chunked framing; send trailers only
  when chunked and the request includes `TE: trailers`. Returning after start
  without finish closes the connection.
- Large plain files use sendfile; HTTPS file sending follows [TLS](tls.md).

## Allocation measurements

[http_routing_allocations](../tests/http_routing_allocations.cc) checks zero
per-request allocations on warmed routed keep-alive paths. Heads first use
256-byte session storage; longer heads allocate a 4 KiB input buffer, released
when remaining input fits again. Expect allocation for requests above that
threshold. Connection setup and directory-listing storage may allocate.
