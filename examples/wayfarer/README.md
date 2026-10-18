# Wayfarer

A curl-style CLI using public eventloop TCP/TLS, HTTP/2, and HTTP/3 client APIs.
One request per invocation, with optional redirect hops; unsupported options
return errors. No private headers/codecs are linked.

## Build and usage

From the repository root:

```sh
cmake -S examples/wayfarer -B /tmp/wayfarer-build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
cmake --build /tmp/wayfarer-build --target wayfarer -j2
/tmp/wayfarer-build/wayfarer --help
/tmp/wayfarer-build/wayfarer http://127.0.0.1:8080/
/tmp/wayfarer-build/wayfarer -X POST -H 'Content-Type: text/plain' -d hello http://127.0.0.1:8080/echo
/tmp/wayfarer-build/wayfarer --http2 -X PUT --data-binary @upload.bin https://localhost:8443/object
/tmp/wayfarer-build/wayfarer --http3-v2 --ca-file cert.pem -O https://127.0.0.1:4433/file.bin
```

`EVENTLOOP_SOURCE_DIR` selects the checkout (default this repository); CMake
adds it as a subdirectory and links `eventloop::eventloop`.

| Option | Behavior |
| --- | --- |
| `--http1.1`, `--http2`, `--http3`, `--http3-v2` | Select protocol; HTTP/3 uses QUIC v1/v2 |
| `-X METHOD`, repeated `-H FIELD` | Method/headers |
| `-d TEXT`, `--data-binary @FILE` | Literal/file body |
| `-i` | Headers before DATA, HTTP/2 and HTTP/3 trailers after body |
| `-I`, `--head` | HEAD plus `-i`; conflicts with body/non-HEAD `-X` |
| `-L` | Up to ten redirects |
| `-o FILE` | Commit completed output to FILE |
| `-O`, `--remote-name` | Derive filename from URL; conflicts with `-o` |
| `--fail` | Exit 22 for final 400..599 |
| `--timeout-ms N` | 1..3600000; default 30000 |
| `--ca-file FILE` | PEM trust file instead of system trust |

URLs support http/https, numeric ports, paths/queries, and bracketed IPv6.
TLS verifies hostnames. Status/metadata go to stderr; stdout carries response
bytes and may be partial on failure. Request storage remains owned until
writes retire. Deadline closes TCP or the HTTP/3 connection, or cancels the
HTTP/2 task, to wake I/O.

## Output files

`-o` writes to an exclusive sibling temporary file, then replaces the destination
only after complete response, flush, and close. Transfer/`--fail`/file errors
remove the temporary and preserve an existing destination. The directory must
allow sibling creation. POSIX rename gives atomic replacement; Windows uses
MoveFileExW/REPLACE_EXISTING, preserving the old file on failure without the
same atomic-visibility guarantee. Neither promises crash persistence.

`-O` drops query/fragment, percent-decodes the last path component, and uses it
as the filename. Empty or `.`/`..` becomes index.html; decoded separators/control
bytes are usage errors. It uses the same replacement policy.

## Redirects

All versions resolve relative/absolute Location and reject HTTPS downgrades.
HTTP/1.1 and HTTP/3 use one connection per hop. HTTP/2 reuses its connection
when the next host resolves to the connected address and port and the
certificate covers it (RFC 9113 9.1.1); a 421 on a reused connection, or a
failure before any output, retries on a new connection. POST changes to GET on 301/302; 303 changes all
but HEAD to GET; 307/308 preserve method/body. Cross-origin redirects drop
Authorization, Cookie, and Proxy-Authorization. HTTP/1.1 replays its buffered
file body; HTTP/2 and HTTP/3 reopen files per attempt/hop. Intermediate bodies
are discarded, while `-i` includes their headers. Loops/ten-hop overflow fail.
Missing Location fails on HTTP/1.1; HTTP/2 and HTTP/3 treat it as a final
response.
HTTP/2/3 require HTTPS targets throughout; HTTP/1.1 can upgrade HTTP to HTTPS.

## Protocol limits

- HTTP/1.1: HTTP/HTTPS, general token methods, repeatable headers, bodies
  <=4 MiB (file bodies buffered). Responses support Content-Length, chunked,
  and connection-close framing. Fields/trailers <=64 KiB, chunk-size lines
  <=128 bytes; other transfer codings fail. No streamed uploads, compression
  decoding, proxies, cookie management, or multipart generation.
- HTTP/2: HTTPS/ALPN h2, general methods, literal bodies <=4 MiB, file uploads
  and sink output <=1 TiB. Uploads obey flow control; output streams as received.
  Headers <=64 KiB/128 fields, frames <=16 KiB. No h2c or push.
  Ownership/errors follow the [client contract](../../docs/http2.md#outbound-client).
- HTTP/3: HTTPS, the HTTP/2 request and body options, and the limits and
  errors of the [client contract](../../docs/http3.md#outbound-client): field
  sections <=64 KiB/128 fields, no QPACK dynamic table or push.

## Automated checks

Standalone checks are opt-in; the root suite does not build Wayfarer.
`run_w3_aioquic.py` tests HTTP/3 with aioquic 1.3.0; `run_w4.py` adds HTTP/1.1,
TLS HTTP/2 (including redirect connection reuse and 421 retry), and `-I`/`-O`.
Without Python h2, CMake skips W4.

```sh
python3 -m venv /tmp/wayfarer-aioquic
/tmp/wayfarer-aioquic/bin/python -m pip install 'aioquic==1.3.0' h2
cmake -S examples/wayfarer -B /tmp/wayfarer-build -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTING=OFF -DWAYFARER_HTTP3_TESTS=ON \
  -DPython3_EXECUTABLE=/tmp/wayfarer-aioquic/bin/python
cmake --build /tmp/wayfarer-build --target wayfarer
ctest --test-dir /tmp/wayfarer-build --output-on-failure
```

Runners also accept `--wayfarer /path/to/wayfarer`: W3 `--version both`,
W4 `--version all`.

## Exit status

0: completed response (including HTTP errors by default); 1: transport/protocol/
output failure; 2: invalid/unsupported arguments; 22: final 400..599 with
`--fail`. Error bodies still stream to stdout; `-o` discards its temporary.
With `-L`, status policy applies to the final response.
