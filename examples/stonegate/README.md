# Stonegate

Stonegate is a static file server built only with the public `eventloop` API.
It can serve plain HTTP/1.1, TLS HTTP/1.1 or HTTP/2, and UDP HTTP/3. It can
optionally redirect HTTP to HTTPS and list directories on HTTP/1.1 and HTTP/2.
The built-in servers own their sockets and document-root descriptors and use
secure path traversal; this program does not implement file walking.

## Build

From the repository root in a source checkout with the HTTP/3 server API:

```sh
cmake -S examples/stonegate -B /tmp/stonegate-build -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/stonegate-build --target stonegate -j2
```

The local CMake file adds the eventloop checkout as a subdirectory. Override
the source location when the HTTP/3 server API lives in another worktree:

```sh
cmake -S examples/stonegate -B /tmp/stonegate-build -DCMAKE_BUILD_TYPE=Release \
  -DEVENTLOOP_SOURCE_DIR=/tmp/eventloop-http3-server
cmake --build /tmp/stonegate-build --target stonegate -j2
```

To use an installed package containing `http3_server`, configure with
`-DEVENTLOOP_SOURCE_DIR= -DCMAKE_PREFIX_PATH=/path/to/eventloop-install`.
OpenSSL 3.5+ is required by the library build.

## Run

```sh
mkdir -p /tmp/stonegate-root
printf 'hello\n' > /tmp/stonegate-root/index.html
/tmp/stonegate-build/stonegate --root /tmp/stonegate-root --bind 127.0.0.1 --http-port 8080
curl --http1.1 http://127.0.0.1:8080/
```

To serve TLS HTTP/1.1 and HTTP/2 and redirect the plain listener:

```sh
/tmp/stonegate-build/stonegate --root /tmp/stonegate-root \
  --certificate cert.pem --private-key key.pem \
  --http-mode redirect --redirect-host localhost \
  --http-port 8080 --https-port 8443
curl --http2 -k https://localhost:8443/
```

Add UDP HTTP/3 on a separate port with the same certificate and private key:

```sh
/tmp/stonegate-build/stonegate --root /tmp/stonegate-root \
  --certificate cert.pem --private-key key.pem \
  --http-mode redirect --redirect-host localhost \
  --http-port 8080 --https-port 8443 --http3-port 8444
curl --http3-only -k https://localhost:8444/
```

The HTTP/3 option requires a certificate and an unencrypted private key.
`--http3-port` defaults to off. The UDP port may have the same number as a TCP
port because they are separate transports. The `--bind` address is shared by
all enabled listeners.

`--http-mode serve` serves plain HTTP alongside HTTPS. `--http-mode off` turns
off plain HTTP while retaining TLS HTTP/1.1 and optionally HTTP/2 and HTTP/3.
`--http2 off` advertises only HTTP/1.1 on TCP TLS. The remaining CLI options
are shown by `--help`. `--reuse-port` applies to TCP listeners only. Press
Ctrl-C to request shutdown. Stonegate closes and awaits the HTTP/3 UDP
endpoint before shutting down the loop. `--shutdown-seconds` sets the loop's
bounded grace deadline; the library requests cancellation of active roots
immediately, so this deadline does not guarantee outstanding responses finish.

## Smoke check

From the repository root after building:

```sh
bash examples/stonegate/smoke.sh /tmp/stonegate-build/stonegate
```

The script creates a temporary document root and certificate, checks plain
HTTP/1.1, HTTP-to-HTTPS redirect, TLS HTTP/1.1, and TLS HTTP/2 when the local
curl supports HTTP/2. It also checks that `--http2 off` negotiates HTTP/1.1,
and exercises HEAD, directory listing, path traversal and outside-root symlink
rejection, the `--reuse-port` setting, and a TLS listener rebind after SIGINT.
When curl advertises HTTP3, the script makes three rounds of fresh HTTP/3
GET, HEAD, OPTIONS, and GET-after-OPTIONS requests against one running
Stonegate process. It checks statuses 200/200/204/200, version 3, GET bodies,
HEAD Content-Length and no body, OPTIONS Allow and no Content-Length or body.
Without curl HTTP3 support, that portion reports SKIP; it does not silently
accept a failed HTTP/3 request.
The three-round smoke sequence and a separate ten-round
GET→HEAD→OPTIONS→GET sequence passed with curl 8.14.1 against the HTTP/3 API
at commit `4d4b74e`. See [TEST_REPORT.md](TEST_REPORT.md) for the observed
coverage and the earlier OPTIONS failure resolved by that API fix.

## Boundaries and unsupported features

- HTTP/3 uses the public `http3_server` API and supports static GET, HEAD, and
  OPTIONS for files and `index.html`. It does not support directory listings,
  request bodies, server push, or WebTransport. The HTTP/3 API currently caps
  active connections at eight, peer bidirectional streams at 32 per
  connection, and peer unidirectional streams at eight. Request headers are
  capped at 16 KiB and 128 fields; QPACK dynamic tables are disabled. The
  public API has no capacity knobs for these limits. The local test report
  records the repeated HTTP/3 acceptance run against API commit `4d4b74e`.
- This is a static document-root server. The public server API exposes no
  application route handlers, reverse proxy, CGI/FastCGI, virtual hosts,
  access logs, compression, cache controls, upload handling, HTTP/2 tuning,
  custom error pages, or live configuration reload. Those cannot be enabled
  by Stonegate's CLI.
- HTTP/2 is TLS only. The built-in server supports GET, HEAD, and OPTIONS,
  with at most 32 active streams per connection, 64 KiB header blocks/lists,
  1 MiB discarded request bodies, and 4 MiB of queued inline response bodies
  per connection. It does not support h2c, cleartext prior knowledge, CONNECT,
  or extended CONNECT.
- The library owns socket I/O and coroutine state. Its bounded frame and queue
  capacities can reject new work under load. This program exposes no knobs
  for those capacities, beyond the listener's `--reuse-port` setting.
- TLS certificate/key loading happens before the listener starts. This
  example does not rotate credentials without restart.
