# Stonegate

Static files over plain HTTP/1.1, TLS HTTP/1.1/2, and UDP HTTP/3, using public
eventloop headers. `GET /healthz` (and implied HEAD) runs through `http::router`.
Library servers own sockets/document roots and secure traversal. Shared
[static-file rules](../../docs/http.md#static-resources) cover validators,
single ranges, HEAD, index preference, and bounded directory listings.

## Build

From the repository root (C++23, CMake 3.20+, OpenSSL 3.5+, threads):

```sh
cmake -S examples/stonegate -B /tmp/stonegate-build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
cmake --build /tmp/stonegate-build --target stonegate -j2
```

`EVENTLOOP_SOURCE_DIR` defaults to this checkout. Set another checkout path,
or use `-DEVENTLOOP_SOURCE_DIR= -DCMAKE_PREFIX_PATH=/path/to/eventloop-install`
for an installed package exporting `eventloop::eventloop`.

## Run

```sh
mkdir -p /tmp/stonegate-root
printf 'hello\n' > /tmp/stonegate-root/index.html
/tmp/stonegate-build/stonegate --root /tmp/stonegate-root --bind 127.0.0.1 --http-port 8080
curl --http1.1 http://127.0.0.1:8080/
```

With an existing certificate/key, enable TLS and redirect plain HTTP:

```sh
/tmp/stonegate-build/stonegate --root /tmp/stonegate-root \
  --certificate cert.pem --private-key key.pem \
  --http-mode redirect --redirect-host localhost \
  --http-port 8080 --https-port 8443
curl --http2 -k https://localhost:8443/
```

Add `--http3-port 8444` for UDP HTTP/3 and test with
`curl --http3-only -k https://localhost:8444/`. HTTP/3 needs an unencrypted key;
TCP and UDP may share a port number. `--bind` applies to every listener.

| Option | Behavior |
| --- | --- |
| `--http-mode serve\|redirect\|off` | Plain HTTP mode; default serve |
| `--http2 on\|off` | TLS h2 advertisement; default on |
| `--http3-port PORT` | HTTP/3; default off |
| `--http3-connections N` | 1..256; default 8 |
| `--http3-requests N` | 1..8192 scratch slots; default four per connection |
| `--http3-max-datagram N` | 1200..8192 bytes; default 1472 |
| `--directory-listing`, `--no-directory-listing` | Listings without index.html |
| `--reuse-port`, `--no-reuse-port` | TCP listener port reuse |
| `--shutdown-seconds N` | Loop grace deadline; default 5 |

See `--help` for remaining options. Ctrl-C closes/awaits HTTP/3 before loop
shutdown. Shutdown cancels roots immediately; grace does not guarantee response
completion. Coroutine capacities scale with configured HTTP/3 capacity.

## Configuration file

Copy [stonegate.conf.example](stonegate.conf.example), create its document
root, and run `stonegate --config FILE`. An existing root is required.
Config loads first regardless of CLI position; CLI settings apply in written
order and override it.

- Nonblank lines are `key=value`; trim surrounding spaces/tabs. Leading `#`
  marks comments. No quoting, escaping, or inline comments; `#`/`=` inside
  values are literal.
- Keys match value-taking CLI names without `--`, plus `directory-listing`
  and `reuse-port`. The three boolean keys (`http2`, `directory-listing`,
  `reuse-port`) accept on/off. HTTP/3 capacity/datagram keys are supported.
  Duplicate/unknown keys, empty/bad values fail with line numbers.
- File-relative root/certificate/key paths resolve beside the config;
  CLI paths resolve from the working directory. `--no-*` overrides file flags.
  Store key passwords in protected local config; diagnostics omit values.

## Limits

HTTP/3 request-pool/frame exhaustion rejects only that request with
H3_REQUEST_REJECTED. Peer stream limits are 32 bidirectional/eight
unidirectional per connection; retired streams replenish credit. Headers are
16 KiB/128 fields; dynamic QPACK, push, and WebTransport are unsupported.
Static request bodies are discarded under the [HTTP/3 rules](../../docs/http3.md).

HTTP/2 is TLS only: 32 active streams, 64 KiB headers, 1 MiB discarded static
bodies, 4 MiB queued inline bodies. No h2c/prior knowledge or ordinary CONNECT.
The library supports route handlers and Extended CONNECT WebSockets;
Stonegate exposes only its health route and static resources.

No CLI support for custom routes, uploads, proxying, CGI, virtual hosts,
access logs, compression, custom cache/error policies, or live reload.
Credentials load before listening and require restart to rotate. General
frame/queue limits remain bounded, without separate CLI tuning.

## Smoke check

```sh
bash examples/stonegate/smoke.sh /tmp/stonegate-build/stonegate
```

The runner creates temporary roots/certificates and covers plain HTTP, redirect,
TLS, ALPN disable, HEAD/OPTIONS, listings, traversal/symlink rejection, reuse,
SIGINT/rebind, config precedence/relative paths/errors, and credential-value
redaction. It checks validators, range forms, large transfers, same-size rewrites
with restored mtime, and listing bytes/limits across available protocols.
HTTP/2 and HTTP/3 require curl support; absent HTTP/3 reports SKIP, failed
requests fail. HTTP/3 runs repeated GET/HEAD/OPTIONS/GET exchanges against one
process. See [shared HTTP](../../docs/http.md), [HTTP/2](../../docs/http2.md),
and [HTTP/3](../../docs/http3.md) for library contracts.
