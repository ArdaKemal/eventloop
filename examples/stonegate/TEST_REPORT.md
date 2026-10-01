# Stonegate local test report

Date: 2026-10-01

The baseline observations below predate the S1 smoke script update and the
separate HTTP/3 OPTIONS library fix. They are retained as history; final S1
acceptance results are recorded first. All network requests used local loopback
listeners and temporary roots, keys, and certificates under `/tmp`.

## S1 acceptance: PASS

The independent tester freshly configured and built against local `main` at
`4d4b74e` with:

```sh
cmake -S /tmp/eventloop-realworld-server/examples/stonegate \
  -B /tmp/stonegate-s1-fresh-build -DCMAKE_BUILD_TYPE=Release \
  -DEVENTLOOP_SOURCE_DIR=/home/anon/eventloop
cmake --build /tmp/stonegate-s1-fresh-build --target stonegate -j2
bash /tmp/eventloop-realworld-server/examples/stonegate/smoke.sh \
  /tmp/stonegate-s1-fresh-build/stonegate
```

Build and smoke passed. The local curl is 8.14.1 and advertises HTTP/2 and
HTTP/3. The smoke covered HTTP/1.1 redirect and TLS, TLS HTTP/2, repeated
HTTP/3 GET/HEAD/OPTIONS/GET, SIGINT shutdown and TLS listener rebind,
HTTP/1.1-only TLS, plain HTTP/1.1, HEAD, directory listing, path traversal,
and outside-root symlink rejection. An additional independent probe passed ten
fresh HTTP/3 connections; each returned GET 200 with the exact body, HEAD 200
with Content-Length 13 and no body, OPTIONS 204 with `Allow: GET, HEAD,
OPTIONS` and no body or Content-Length, then GET 200 with the exact body.
SIGINT then produced a clean server exit.

The failure-path probe ran `smoke.sh` with a temporary server wrapper that
printed two sentinel lines and exited 23. The smoke command returned nonzero,
printed both server log lines before cleanup, and removed the temporary log
directory. `git diff --check` and no-index whitespace checks for the untracked
Stonegate files were clean.

An initial smoke invocation without loopback socket permission failed with
`Operation not permitted`; the same local test passed after loopback access was
granted. Build warnings were limited to existing QUIC sources:
`sent_packet_history.h`'s missing `template` suggestion and a signed/unsigned
comparison in `transport_parameters.h`. Stonegate itself compiled without
warnings.

## Build

Command:

```sh
cmake -S /tmp/eventloop-realworld-server/examples/stonegate \
  -B /tmp/stonegate-test-build -DCMAKE_BUILD_TYPE=Release \
  -DEVENTLOOP_SOURCE_DIR=/tmp/eventloop-http3-server
cmake --build /tmp/stonegate-test-build --target stonegate -j2
```

Result: **PASS**. CMake found OpenSSL 3.5.6 and built `stonegate` against the
HTTP/3 API worktree. The build emitted two warnings in the eventloop QUIC
sources (`sent_packet_history.h`: missing `template` keyword suggestion;
`transport_parameters.h`: signed/unsigned comparison). No Stonegate source
warning was emitted.

## Baseline smoke script before S1

Command:

```sh
bash /tmp/eventloop-realworld-server/examples/stonegate/smoke.sh \
  /tmp/stonegate-test-build/stonegate
```

Result: **PASS**. Output:

```text
HTTP/1.1 redirect and TLS response: PASS
TLS HTTP/2 response: PASS
TLS HTTP/1.1 only: PASS
Plain HTTP/1.1 response: PASS
HEAD and directory listing: PASS
```

The first attempt in the restricted shell failed immediately with
`stonegate: socket: Operation not permitted`. Rerunning this local-only test
with loopback socket access succeeded; this was a sandbox restriction, not an
application failure.

## Focused protocol and resource checks

The local curl is 8.14.1 and advertises both HTTP2 and HTTP3 features. The
`aioquic` Python package is not installed. HTTP/3 was therefore exercised with
curl, rather than aioquic.

| Check | Result |
| --- | --- |
| HTTP/1.1 GET `/` and `/sub/` | **PASS**, returned the respective `index.html` bodies |
| HTTP/1.1 HEAD `/` | **PASS**, status 200 and zero downloaded body bytes |
| HTTP/1.1 OPTIONS `/dir/file.txt` | **PASS**, status 204 and an `Allow` header listing GET, HEAD, OPTIONS |
| HTTP/1.1 directory listing `/dir/` with `--directory-listing` | **PASS**, listing contained `file.txt` |
| TLS HTTP/2 OPTIONS `/dir/file.txt` | **PASS**, status 204 and an `Allow` header listing GET, HEAD, OPTIONS |
| HTTP/3 GET `/` | **PASS**, status 200, negotiated HTTP version 3, body matched `index.html` |
| HTTP/3 HEAD `/` | **PASS**, status 200, HTTP/3 headers included `content-length: 12`, no body bytes |
| HTTP/3 OPTIONS `/` before the separate library fix | **FAIL**, no response; curl timed out after 8 seconds with exit status 28 |
| Traversal `/..%2foutside.txt` and `/%2e%2e/outside.txt` | **PASS**, both returned 400 and disclosed no outside content |
| Symlink `/leak.txt` pointing outside the document root | **PASS**, returned 404 and disclosed no outside content |

The HTTP/3 OPTIONS failure is reproducible with a running local Stonegate
HTTP/3 endpoint and:

```sh
curl --http3-only -vk -X OPTIONS --max-time 8 \
  https://127.0.0.1:$HTTP3_PORT/
```

Observed tail of curl output:

```text
> OPTIONS / HTTP/3
> Host: 127.0.0.1:58362
> User-Agent: curl/8.14.1
> Accept: */*
>
* Operation timed out after 8002 milliseconds with 0 bytes received
curl: (28) Operation timed out after 8002 milliseconds with 0 bytes received
```

The port above was dynamically selected for that run; substitute the current
local HTTP/3 port. This is a server/API runtime behavior, not a missing client
capability: curl negotiated HTTP/3 successfully for GET and HEAD against the
same server setup.

## CLI, certificate, and listener checks

Commands below use the temporary `$ROOT`, `$CERT`, and `$KEY` created for the
run. Each invalid invocation returned status 1:

| Invocation | Observed error |
| --- | --- |
| `stonegate` | `stonegate: --root must name an existing directory` |
| `stonegate --root "$ROOT" --http-port 0` | `stonegate: --http-port has an invalid value` |
| `stonegate --root "$ROOT" --certificate "$CERT" --http-mode off` | `stonegate: --certificate and --private-key must be supplied together` |
| `stonegate --root "$ROOT" --http3-port 443` | `stonegate: --http3-port requires --certificate and --private-key` |
| `stonegate --root "$ROOT" --http-mode off --https-port 49231 --certificate "$BAD_CERT" --private-key "$KEY"` | `stonegate: cannot load certificate chain` |

For port behavior, a second Stonegate process configured for an already-bound
TCP port exited with status 1 and `stonegate: bind: Address already in use`.
After sending SIGINT to the first process, it exited and a new process bound
the same port successfully. The smoke script also started its plain listener
with `--reuse-port` successfully.

## Whitespace check

`git diff --no-index --check /dev/null TEST_REPORT.md` produced no whitespace
diagnostics (exit 1 only because the untracked report differs from `/dev/null`).
