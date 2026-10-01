# Wayfarer

`Wayfarer` is a small curl-style command line client built with eventloop's
public TCP, TLS, HTTP/2, and QUIC APIs. It makes one request per invocation.
Requested features run through eventloop or return a clear error.

## Build

From the repository root:

```sh
cmake -S examples/wayfarer -B /tmp/wayfarer-build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF \
  -DEVENTLOOP_SOURCE_DIR=/home/anon/eventloop
cmake --build /tmp/wayfarer-build --target wayfarer -j2
```

`EVENTLOOP_SOURCE_DIR` defaults to the repository root of this example's
checkout. Set it to a checkout with `include/eventloop/http2/client.h` for
the HTTP/2 build. The local CMake project adds that source tree as a
subdirectory and links `eventloop::eventloop`. No root CMake changes are needed.

## Usage

```sh
/tmp/wayfarer-build/wayfarer --help
/tmp/wayfarer-build/wayfarer https://example.org/
/tmp/wayfarer-build/wayfarer -X POST -H 'Content-Type: text/plain' -d 'hello' -o response.txt http://127.0.0.1:8080/echo
/tmp/wayfarer-build/wayfarer --http2 -X POST -H 'Content-Type: text/plain' -d 'hello' -o response.txt https://example.org/echo
/tmp/wayfarer-build/wayfarer --http2 -X PUT --data-binary @upload.bin https://example.org/object
/tmp/wayfarer-build/wayfarer --http2 -L -i -o response-with-headers.txt https://example.org/redirect
/tmp/wayfarer-build/wayfarer --http2 -i -H 'Accept: text/html' https://example.org/
/tmp/wayfarer-build/wayfarer --http3 --timeout-ms 5000 https://cloudflare.com/
/tmp/wayfarer-build/wayfarer --http3-v2 --ca-file cert.pem https://127.0.0.1:4433/
```

`-i` includes HTTP/1.1 or HTTP/2 response headers in the output. Status and errors go
to stderr. `-o` writes binary response output to a file. The default timeout
is 30 seconds; `--timeout-ms` accepts 1 through 3,600,000. URL parsing supports
`http://` and `https://`, numeric ports, paths, queries, and bracketed IPv6.
TLS verifies the hostname against the system trust store or a PEM trust file
selected with `--ca-file`. The user-supplied request body remains owned by the
CLI until all writes complete. HTTP/2 copies literal `-d` data into its owned
bounded body buffer; `--data-binary @FILE` reopens the file for each attempt
and supplies chunks under HTTP/2 flow control. HTTP/2 response DATA
streams to stdout or `-o` as it arrives. With `-i`, each response header block
is written before the following DATA; trailers are written after the body.
Closing the socket, cancelling the
HTTP/2 request task, or closing the QUIC endpoint on deadline wakes pending I/O.
`-d` sends literal text; `--data-binary @FILE` reads a binary file. HTTP/1.1
buffers that file with a 4 MiB limit. HTTP/2 streams the file with a 1 TiB
limit set by the public API.

`-L` follows up to ten HTTP/2 redirects to HTTPS URLs. For 301/302, POST
becomes GET; for 303, all methods except HEAD become GET; 307/308 preserve
method and body. File bodies are reopened for preserved uploads. A redirect
to another origin drops Authorization, Cookie, and Proxy-Authorization headers.
Intermediate redirect bodies are discarded; `-i` still writes their headers.

| Version | Implemented | Deliberate limits / failure |
| --- | --- | --- |
| HTTP/1.1 | HTTP and HTTPS; GET, HEAD, POST and other token methods with `-X`; repeatable `-H`; `-d` or `--data-binary @FILE` body up to 4 MiB; body or headers plus body output; Content-Length, chunked, and connection-close responses | One request and connection per run; no redirect following, compression decoding, proxy, cookies, multipart, or upload streaming. Response fields are capped at 64 KiB; chunk size lines at 128 bytes. Other Transfer-Encoding values fail. |
| HTTP/2 | HTTPS methods including GET, HEAD, POST, PUT, PATCH, DELETE and OPTIONS; request headers; `-d` body up to 4 MiB; `--data-binary @FILE` streamed upload up to 1 TiB; TLS verification and ALPN `h2`; streamed stdout or `-o` output; `-i` streams headers, body, and trailers; `-L` follows redirects | One connection per request or redirect hop. The sink API accepts up to 1 TiB of response DATA. Header blocks are limited to 64 KiB and 128 fields; incoming frames to 16 KiB. No cleartext h2c, connection reuse, or push. Capacity and protocol errors come from the public API. |
| HTTP/3 | HTTPS GET over public QUIC v1 or v2; TLS verification; body output | Request HEADERS are capped at 4 KiB. The response parser accepts a static QPACK `:status` as the first field, including literal decimal Huffman status values; other QPACK forms fail. Each complete response frame is capped at 64 KiB and total DATA at 16 MiB. Custom method, headers, body and `-i` fail at argument parsing. No redirect following, push, dynamic QPACK, trailers, or response field reporting. |

HTTP/3 uses a fixed static QPACK request header block and opens client control,
encoder, and decoder streams. It does not include or link any private eventloop
headers or source. The narrow response decoder makes it useful for exercising
public QUIC as a real HTTP/3 caller, but it is not a complete HTTP/3 client.
The complete in-tree `http3_client` example uses private HTTP/3 codec headers;
that implementation is outside this program's public-API-only constraint.

## Checks and observed failures

- Local Python HTTP server: GET with Content-Length, GET with chunked encoding,
  POST with `-d payload`, and HEAD returned exit 0 with expected output.
- Standalone HTTP/2 build against the expanded public API completed without
  warnings. A local TLS HTTP/2 fixture checked a 6 MiB download to `-o`, a
  6 MiB sourced upload and echoed response, and `-i` ordering for informational
  headers, final headers, DATA, and trailers.
- The same fixture checked POST and PUT through 301, 302, 303, 307, and 308;
  HEAD through 303; file replay on preserved uploads; discarded intermediate
  bodies; `-L -i` header ordering; same-origin credential preservation;
  cross-origin credential removal; redirects without Location; the ten-hop
  limit; and rejection of redirects to plain HTTP.
- Public `https://cloudflare.com/` with `--http3 --timeout-ms 5000` completed
  a QUIC/TLS handshake, decoded an HTTP/3 301 response, and wrote its body.
  The program does not follow that redirect.
- The first HTTP/3 public attempt failed on a literal QPACK status field;
  the bounded decoder now recognizes the observed form. Other dynamic or
  unsupported QPACK forms still fail explicitly.

Exit status is 0 for a completed response, 1 for transport/protocol/output
failure, and 2 for invalid or unsupported command line options. HTTP error
statuses such as 404 still count as completed responses, matching curl's
default behavior without `--fail`.
