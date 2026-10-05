# HTTP/1.1 API contract

The [coroutine and event-loop contract](coroutines.md) defines task results, loop affinity,
borrowed-buffer lifetimes, and cancellation. The [shared HTTP contract](http.md)
defines routing and request/response operations. Read those rules together with
this protocol's limits and behavior; the other HTTP protocol contracts are not
required for changes confined to this protocol.

## Servers and handler storage

`http::server` serves plain HTTP/1.1. `http::https_server` serves HTTP/1.1 when
ALPN selects `http/1.1`; it also advertises `h2` by default. Set
`server_options::enable_http2` to `false` to disable HTTP/2.

- HTTP/1.1 runs one handler at a time per connection. Routing state, a 4 KiB
  response buffer, and the request view are allocated once per connection
  when the server has routes.

## Request bodies

- HTTP/1.1 bodies use Content-Length or `Transfer-Encoding: chunked`.
  Chunk extensions are skipped and request trailers are checked for a
  name and colon, then dropped. Chunk-size lines are limited to 1 KiB
  and the trailer section to 8 KiB. A malformed chunked body returns
  `bad_message` and answers 400 if the handler returns without a
  response. A read past `max_request_body` returns `message_size` and
  answers 413 the same way. Either one closes the connection.
  Content-Length together with chunked answers 400; other transfer
  codings, and chunked bodies on static requests, answer 501. A chunked
  body on a routed path without a handler for the method gets its 204 or
  405 and the connection closes. The first body read answers
  `Expect: 100-continue` with 100 Continue.

- An unread request body is discarded before the next request on the
  connection, except after `Expect: 100-continue` without a read, which
  closes the connection.

## Responses and connection reuse

- Without content-length, responses use chunked transfer coding. Trailers are
  sent only on chunked responses to requests with `TE: trailers`.
- A handler that returns after `async_start` but before `async_finish` closes
  the connection.
- Large plain HTTP file responses use `sendfile`. HTTPS HTTP/1.1 file responses
  use the TLS file-send path described in the [TLS contract](tls.md).

## Allocation measurements

`tests/http_routing_allocations.cc` checks that steady-state routed requests on
a kept-alive connection make no general-heap allocation in the measured paths.
An HTTP/1.1 connection reads request heads into 256 bytes of session storage;
a longer head allocates one 4 KiB input buffer, released once the remaining
input fits again, so idle connections stay small. A browser request head is
usually longer, so expect one allocation per such request. Connection setup
and the shared directory-listing renderer may allocate.
