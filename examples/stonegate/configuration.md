# Stonegate configuration contract

Stonegate reads TOML with the public `eventloop::util::parse_toml` API.
This replaces the old unquoted key=value format. CLI-only invocations continue
working. The deployment use case is several static sites on separate numeric
IP/port endpoints, with common policy and files split by site.

## Structure and inheritance

The main file accepts `include` (an array of exact file paths), `[runtime]`,
`[defaults]`, and `[[server]]` tables. Included files accept only `include`
and `[[server]]`. Includes are visited in array order, depth first, before
servers in the including file. Globs and environment substitution are absent.
The main file's defaults apply to every server regardless of include order.
Each server copies those defaults, then overrides only its explicit fields;
nested protocol tables merge by field. Server names are unique, optional,
and otherwise generated as `server-1`, `server-2`, etc. Names label servers;
they do not match HTTP Host or TLS SNI.

If no server tables exist anywhere, defaults form one implicit server.
All paths resolve beside the file defining that value; inherited paths retain
that resolution. CLI paths resolve from the working directory. CLI settings
apply after the complete configuration, in written order, regardless of
`--config` position. With multiple servers, server options require
`--server NAME`; this selects one server for all CLI overrides. `--server`
does not prevent other servers from running. `--shutdown-seconds` and `--check`
are global.

## Schema

Unknown keys/tables, duplicate TOML keys, wrong types, invalid values, missing
roots/credentials, duplicate names, and overlapping endpoints fail startup.
Strings must exclude NUL. Diagnostics omit setting values and source lines; config filenames and
setting/server names identify the error. Syntax errors give file, line, column and error category;
schema errors give file and dotted setting path. Cross-field validation errors
identify the merged server.

Fields below are allowed under both `defaults` and each `server`.

| Field | Type | Default / bounds |
| --- | --- | --- |
| `root` | string path | Required existing directory |
| `bind` | string | `127.0.0.1`; numeric IPv4/IPv6, optional numeric IPv6 scope |
| `directory_listing` | boolean | `false` |
| `reuse_port` | boolean | `false`; every listener |
| `open_file_cache_capacity` | integer | 0 (off); 0..65536 descriptors per serving listener |
| `header_timeout_ms` | integer | 30000; 0..3600000, 0 disables; TCP only, including redirect |
| `idle_timeout_ms` | integer | 60000; 0..3600000, 0 disables; serving TCP only |
| `http.mode` | string | `serve`; `serve`, `redirect`, `off` |
| `http.port` | integer | 8080; 1..65535 |
| `http.redirect_host` | string | `localhost`; hostname for HTTPS redirects |
| `tls.port` | integer | 8443; 0..65535, 0 disables TCP TLS |
| `tls.certificate` | string path | PEM certificate chain; empty clears inheritance |
| `tls.private_key` | string path | PEM key; empty clears inheritance |
| `tls.key_password` | string | Empty; protect config file permissions |
| `tls.http2` | boolean | `true`; ALPN advertisement |
| `http3.port` | integer | 0 (off); 0..65535, UDP |
| `http3.connections` | integer | 8; 1..256 per server |
| `http3.requests` | integer | 0 (four per connection); 0..8192 per server |
| `http3.max_datagram` | integer | 1472; 1200..8192 bytes |

`server.name` is a nonempty string, at most 64 ASCII letters, digits, `_`, `-`
or `.`. `[runtime]` accepts `shutdown_seconds` (integer, default 5, 0..3600)
and `workers` (integer, default 1, 1..256). TLS credentials must be paired.
Redirect requires TCP TLS; HTTP-off requires an enabled TLS or HTTP/3
listener. HTTP/3 requires credentials and an unencrypted key. TCP HTTP and TLS
cannot share an endpoint. TCP and UDP may share a port. Servers cannot overlap
numeric addresses/ports within a transport, including wildcard/specific-address
overlap; IPv6 is v6-only.
`reuse_port` lets separate Stonegate processes share listener ports. A
redirect listener closes after one response, so only `header_timeout_ms`
applies to it.

## Validation, bounds, and lifecycle

`stonegate --config FILE --check` validates the merged configuration and loads
TLS credentials without opening listening sockets or starting an event loop.
It does not predict port availability, validate certificate trust/hostname,
or guarantee secure traversal of roots; listeners retain the library's secure
root opens. Credentials load before listening and require restart to rotate.

Limits: 16 servers, 32 files including the main file, include depth 8 (main
file is depth 1), 64 KiB per file, 1 MiB combined input, 2048 TOML nodes and
64 KiB decoded strings per file. Repeated/cyclic includes are rejected using
canonical paths. Capacity failures produce explicit errors. File reads and
configuration/TLS setup may allocate; parsed views are copied into owned
settings before parser buffers expire. Includes use ordinary filesystem access;
only load trusted configuration files.

All servers share one loop on its owning thread on Linux, macOS, and Windows.
With `workers` above 1, each worker thread runs its own loop and opens every
listener itself with SO_REUSEPORT, so the kernel spreads TCP connections and
UDP datagrams across workers; the router and TLS contexts are shared. HTTP/3
connection IDs carry the worker index. This needs the kernel to balance
reuse-port groups, so `workers` above 1 is rejected outside Linux for now.
HTTP/3 capacities and coroutine pools apply per worker. A worker's HTTP/3
connection stalls if the client address changes (see the library's
[QUIC port sharing](../../docs/quic.md#port-sharing)). The first startup error
stops every worker.
Windows builds without TCP TLS support accept only plain HTTP in Stonegate.
TCP listeners/sockets belong to the loop. HTTP/3 listeners and observed run
handles stay in stable caller storage until endpoint/task retirement, including
partial startup failure. Aggregate HTTP/3 capacities size bounded coroutine
pools; request buffers remain owned by library servers. SIGINT or SIGTERM stops
all listeners on every worker. Shutdown cancels roots immediately; the deadline
does not drain responses. No per-request configuration parsing or storage is introduced.

## Migration from key=value

Move `root`, `bind`, `directory-listing`, and `reuse-port` into `[defaults]`,
using snake_case keys. Move `http-port`, `http-mode`, and `redirect-host` into
`[defaults.http]` as `port`, `mode`, and `redirect_host`. Move `https-port`,
`certificate`, `private-key`, `key-password`, and `http2` into `[defaults.tls]`;
`https-port` becomes `port`, and other hyphens become underscores.
Move `http3-*` into `[defaults.http3]`, removing the `http3-` prefix and replacing
remaining hyphens with underscores. Move `shutdown-seconds` into `[runtime]`
as `shutdown_seconds`. Quote strings and use `true`/`false` for booleans.
CLI spellings continue to use hyphens and `--http2 on|off`.
