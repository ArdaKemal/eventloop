# Stonegate

Stonegate is a static file server built only with the public `eventloop` API.
It can serve plain HTTP/1.1, TLS HTTP/1.1 or HTTP/2, and UDP HTTP/3. It can
optionally redirect HTTP to HTTPS and list directories on all three HTTP
versions when the directory has no index file.
The built-in servers own their sockets and document-root descriptors and use
secure path traversal; this program does not implement file walking.
`GET /healthz` answers `ok` through a route registered with the public
`http::router`; it runs on HTTP/1.1 and HTTP/3 connections, while HTTP/2
serves that path from the document root.
Static files include ETag and Last-Modified validators and support single
byte ranges on all three HTTP versions. A matching `If-None-Match` (which
takes precedence over `If-Modified-Since`) or `If-Modified-Since` returns
304. Closed, open-ended, and suffix ranges return 206; unsatisfiable single
ranges return 416. Multiple ranges are ignored and return the full file.
HEAD sends the corresponding GET status and headers without a body.

## Build

From the repository root:

```sh
cmake -S examples/stonegate -B /tmp/stonegate-build -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/stonegate-build --target stonegate -j2
```

The local CMake file adds the eventloop checkout as a subdirectory. To build
against a different checkout, set its source path explicitly:

```sh
cmake -S examples/stonegate -B /tmp/stonegate-build -DCMAKE_BUILD_TYPE=Release \
  -DEVENTLOOP_SOURCE_DIR=/path/to/eventloop
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

## Configuration file

Copy [stonegate.conf.example](stonegate.conf.example) to a local config file,
create its `public` directory, and run `stonegate --config /path/to/stonegate.conf`.
`--root` or `--config` must provide an existing document root. CLI options may
appear before or after `--config`; Stonegate loads the file first and then
applies CLI options in their written order, so a CLI value overrides the file.
For example, `stonegate --config stonegate.conf --http-port 9090` changes the
port without editing the file.

Each nonblank line is `key=value`. Spaces and tabs around the key, `=`, and
value are ignored. Lines whose first nonwhitespace character is `#` are
comments. There are no inline comments, quotes, or escape sequences; a `#` or
`=` inside a value is literal. Keys use the CLI names without `--`, including
`root`, `bind`, `http-port`, `http-mode`, `https-port`, `http3-port`,
`certificate`, `private-key`, `key-password`, `redirect-host`, `http2`,
`directory-listing`, `reuse-port`, and `shutdown-seconds`. The three boolean
keys use `on` or `off`. Duplicate keys, unknown keys, empty values, and
malformed values are errors with a line number. Relative `root`, `certificate`,
and `private-key` paths in the file resolve relative to the config file's
directory; CLI paths resolve relative to the current working directory.
`--no-directory-listing` and `--no-reuse-port` can override enabled file
settings. Keep private key passwords in a protected local config file; the
example has no credentials and error messages do not print setting values.

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
It checks config and CLI equivalence, config-relative paths, CLI overrides,
duplicate and malformed settings, missing TLS credentials, conflicting ports,
and error messages that do not echo a private key password.
When curl advertises HTTP3, the script makes three rounds of fresh HTTP/3
GET, HEAD, OPTIONS, and GET-after-OPTIONS requests against one running
Stonegate process. It checks statuses 200/200/204/200, version 3, GET bodies,
HEAD Content-Length and no body, OPTIONS Allow and no Content-Length or body.
Without curl HTTP3 support, that portion reports SKIP; it does not silently
accept a failed HTTP/3 request.
The smoke check also exercises validators, range forms, unsatisfiable and
multiple ranges, HEAD ranges, a large streamed range, and a same-size file
rewrite with restored modification time on every available HTTP version.
It also compares the generated directory listing byte for byte across HTTP/1.1,
HTTP/2, and HTTP/3, including escaped hrefs and text, hidden entries, stable
name order, index preference, a symlink entry, and the entry-limit error.

## Boundaries and unsupported features

- HTTP/3 uses the public `http3_server` API and supports static GET, HEAD, and
  OPTIONS for files, `index.html`, and (when constructed with
  `directory_listing`) bounded directory listings. It does not support request
  bodies, server push, or WebTransport. `--http3-connections` sets the
  simultaneous connection capacity from 1 to 256; the default is eight.
  `--http3-requests` reserves from 1 to 8192 reusable request scratch buffers;
  the default is four per connection. A full request pool closes the affected
  connection.
  The QUIC transport caps simultaneously active peer bidirectional streams
  at 32 per connection and peer unidirectional streams at eight. Completed
  streams release storage and replenish the peer's stream credit. Request headers
  are capped at 16 KiB and 128 fields; QPACK dynamic tables are disabled.
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
