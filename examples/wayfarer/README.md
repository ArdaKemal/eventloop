# Wayfarer

`Wayfarer` is a small curl-style command line client built with eventloop's
public TCP, TLS, HTTP/2, and QUIC APIs. It makes one request per invocation.
Requested features run through eventloop or return a clear error.

## Build

From the repository root:

```sh
cmake -S examples/wayfarer -B /tmp/wayfarer-build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
cmake --build /tmp/wayfarer-build --target wayfarer -j2
```

`EVENTLOOP_SOURCE_DIR` defaults to this checkout's repository root. The local
CMake project adds it as a subdirectory and links `eventloop::eventloop`.

## Usage

```sh
/tmp/wayfarer-build/wayfarer --help
/tmp/wayfarer-build/wayfarer https://example.org/
/tmp/wayfarer-build/wayfarer -X POST -H 'Content-Type: text/plain' -d 'hello' -o response.txt http://127.0.0.1:8080/echo
/tmp/wayfarer-build/wayfarer --http2 -X POST -H 'Content-Type: text/plain' -d 'hello' -o response.txt https://example.org/echo
/tmp/wayfarer-build/wayfarer --http2 -X PUT --data-binary @upload.bin https://example.org/object
/tmp/wayfarer-build/wayfarer --http2 -L -i -o response-with-headers.txt https://example.org/redirect
/tmp/wayfarer-build/wayfarer --http1.1 -L -i http://example.org/redirect
/tmp/wayfarer-build/wayfarer --http2 -i -H 'Accept: text/html' https://example.org/
/tmp/wayfarer-build/wayfarer --http3 --timeout-ms 5000 https://cloudflare.com/
/tmp/wayfarer-build/wayfarer --http3 -L -i https://example.org/redirect
/tmp/wayfarer-build/wayfarer --http3-v2 -X HEAD -i https://example.org/
/tmp/wayfarer-build/wayfarer --http3-v2 --ca-file cert.pem https://127.0.0.1:4433/
/tmp/wayfarer-build/wayfarer --fail -o page.html https://example.org/page.html
/tmp/wayfarer-build/wayfarer --http2 -I https://example.org/
/tmp/wayfarer-build/wayfarer -O https://example.org/files/report.txt?version=2
/tmp/wayfarer-build/wayfarer --http3 -O --ca-file cert.pem https://127.0.0.1:4433/file.bin
```

`-i` includes HTTP/1.1, HTTP/2, or HTTP/3 response headers in the output.
`-I`/`--head` sends a HEAD request and implies `-i`; it cannot be combined with
a request body or with a conflicting `-X`. Status and transfer metadata go to
stderr so stdout stays suitable for pipelines. `-o` writes binary response output to an exclusive sibling temporary
file, then replaces the named file after the complete response, successful
flush and close. A failed transfer, HTTP error with `--fail`, or failed file
operation removes the temporary file and leaves an existing destination intact.
The sibling rename provides atomic replacement on POSIX filesystems. Windows
uses `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING`; this preserves the old file
if replacement fails, but Windows does not promise the same atomic visibility.
The destination must be in a directory where Wayfarer can create a sibling
file. `-O`/`--remote-name` derives the destination from the URL instead: the
query and fragment are dropped, percent escapes are decoded, and the final path
component is used. Empty and `.`/`..` components become `index.html`; a
component that still contains a path separator or control byte is rejected as a
usage error. An existing file is replaced under the same atomic policy as `-o`,
and `-O` and `-o` are mutually exclusive. This does not guarantee persistence across a system crash. Without `-o`, output streams
to stdout and may be partial when a request fails. The default timeout
is 30 seconds; `--timeout-ms` accepts 1 through 3,600,000. URL parsing supports
`http://` and `https://`, numeric ports, paths, queries, and bracketed IPv6.
TLS verifies the hostname against the system trust store or a PEM trust file
selected with `--ca-file`. The user-supplied request body remains owned by the
CLI until all writes complete. HTTP/2 copies literal `-d` data into its owned
bounded body buffer; `--data-binary @FILE` reopens the file for each attempt
and supplies chunks under HTTP/2 flow control. HTTP/2 response DATA
streams to stdout or the temporary `-o` file as it arrives. With `-i`, each response header block
is written before the following DATA; trailers are written after the body.
Closing the socket, cancelling the
HTTP/2 request task, or closing the QUIC endpoint on deadline wakes pending I/O.
`-d` sends literal text; `--data-binary @FILE` reads a binary file. HTTP/1.1
buffers that file with a 4 MiB limit. HTTP/2 streams the file with a 1 TiB
limit set by the public API.

`-L` follows up to ten HTTP/1.1, HTTP/2, or HTTP/3 redirects. HTTP/1.1 and HTTP/3 accept relative
and absolute Location values, including redirects from HTTP to HTTPS. HTTPS to
HTTP downgrades are rejected. For 301/302, POST
becomes GET; for 303, all methods except HEAD become GET; 307/308 preserve
method and body. HTTP/1.1 replays its bounded 4 MiB file body; HTTP/2 reopens
the file for each preserved upload. A redirect
to another origin drops Authorization, Cookie, and Proxy-Authorization headers.
Intermediate redirect bodies are discarded; `-i` still writes their headers.
The body output is from the final response. Missing Location, redirect loops,
and the ten-hop limit are reported as errors. A failed `-o` transfer leaves the
existing destination intact even if earlier hops produced headers.

| Version | Implemented | Deliberate limits / failure |
| --- | --- | --- |
| HTTP/1.1 | HTTP and HTTPS; GET, HEAD, POST and other token methods with `-X`; repeatable `-H`; `-d` or `--data-binary @FILE` body up to 4 MiB; body or headers plus body output; Content-Length, chunked, and connection-close responses; `-L` redirects | One connection per request or redirect hop; no compression decoding, proxy, cookies, multipart, or upload streaming. Response fields are capped at 64 KiB; chunk size lines at 128 bytes. Other Transfer-Encoding values fail. |
| HTTP/2 | HTTPS methods including GET, HEAD, POST, PUT, PATCH, DELETE and OPTIONS; request headers; `-d` body up to 4 MiB; `--data-binary @FILE` streamed upload up to 1 TiB; TLS verification and ALPN `h2`; streamed stdout or `-o` output; `-i` streams headers, body, and trailers; `-L` follows redirects | One connection per request or redirect hop. The sink API accepts up to 1 TiB of response DATA. Header blocks are limited to 64 KiB and 128 fields; incoming frames to 16 KiB. No cleartext h2c, connection reuse, or push. Capacity and protocol errors come from the public API. |
| HTTP/3 | HTTPS GET and HEAD over public QUIC v1 or v2; TLS verification; body output; `-i` response fields; `-L` follows up to ten 301/302/303/307/308 redirects | Request HEADERS are capped at 4 KiB. Response fields accept static QPACK indexed fields, static-name literal values, and literal names and values, including fixed Huffman encoding. Field sections are capped at 64 KiB and 128 decoded fields; each complete response frame is capped at 64 KiB and total DATA at 16 MiB. A present Content-Length is checked against the received DATA, so truncated or overlong bodies fail. Custom methods, request headers, and request bodies fail at argument parsing. Dynamic QPACK and trailers fail as protocol errors; server push is unsupported. |

`-I`/`--head` and `-O`/`--remote-name` are command-line features and apply to
every supported version.

HTTP/3 uses a fixed static QPACK request header block and opens client control,
encoder, and decoder streams. It does not include or link any private eventloop
headers or source. The narrow response decoder makes it useful for exercising
public QUIC as a real HTTP/3 caller, but it is not a complete HTTP/3 client.
The root test suite keeps a broader HTTP/3 client fixture that uses private
codec headers. Wayfarer itself uses only public eventloop headers.

## Automated checks

`tests/run_w3_aioquic.py` drives a controlled aioquic 1.3.0 peer for the HTTP/3
response client, and `tests/run_w4.py` adds HTTP/1.1 and TLS HTTP/2 peers plus
the `-I`/`-O` CLI behavior. Wayfarer is a standalone example project, so the
root eventloop test suite does not build it; enable the checks in the Wayfarer
build instead. The W4 HTTP/2 checks need the `h2` package in the same
interpreter as aioquic:

```sh
python3 -m venv /tmp/wayfarer-aioquic
/tmp/wayfarer-aioquic/bin/python -m pip install 'aioquic==1.3.0' h2
cmake -S examples/wayfarer -B /tmp/wayfarer-build -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTING=OFF -DWAYFARER_HTTP3_TESTS=ON \
  -DPython3_EXECUTABLE=/tmp/wayfarer-aioquic/bin/python
cmake --build /tmp/wayfarer-build --target wayfarer
ctest --test-dir /tmp/wayfarer-build --output-on-failure
```

The runners also work standalone:

```sh
/tmp/wayfarer-aioquic/bin/python examples/wayfarer/tests/run_w3_aioquic.py \
  --wayfarer /tmp/wayfarer-build/wayfarer --version both
/tmp/wayfarer-aioquic/bin/python examples/wayfarer/tests/run_w4.py \
  --wayfarer /tmp/wayfarer-build/wayfarer --version all
```

## Exit status

Exit status is 0 for a completed response, 1 for transport/protocol/output
failure, and 2 for invalid or unsupported command line options. HTTP error
statuses such as 404 still count as completed responses by default. `--fail`
returns 22 for a completed final response with status 400–599 across HTTP/1.1,
HTTP/2 and HTTP/3. With `-L`, all supported protocols apply this rule to the final redirect
response. Error response bodies still stream to stdout; with `-o`, they are
discarded along with the temporary file. Unsupported HTTP/3 QPACK
representations fail as protocol errors (exit 1).
