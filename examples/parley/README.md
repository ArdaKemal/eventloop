# Parley

Parley is a WhatsApp-style chat application built on eventloop's public API.
The browser client is plain HTML, CSS, and JavaScript; the server is one
event loop that serves it over TLS HTTP/2 (and optionally HTTP/3).

- One-to-one and group chats, with history paging and replies.
- Photos, voice notes recorded in the browser, audio files, and documents
  up to 16 MiB.
- Realtime delivery, sent/delivered/read ticks, typing and recording
  indicators, and online/last-seen presence.
- Accounts with PBKDF2 password hashing on worker threads, and sessions in
  `HttpOnly`, `Secure`, `SameSite=Strict` cookies.
- State is kept in a JSON-lines journal and replayed on start.

## Build and run

```sh
cmake -S examples/parley -B build-parley -DCMAKE_BUILD_TYPE=Release
cmake --build build-parley --target parley
./build-parley/parley            # https://localhost:8443/
```

On first start, Parley writes a self-signed certificate for `localhost`,
`127.0.0.1`, and `::1` into the data directory (`parley-data/` by default).
Your browser shows a certificate warning for it; pass `--certificate` and
`--private-key` to use your own. Microphone recording needs the secure
context that HTTPS provides.

| Option | Default | Meaning |
| --- | --- | --- |
| `--bind ADDRESS` | `127.0.0.1` | Numeric IPv4 or IPv6 listen address |
| `--port PORT` | `8443` | TLS port, and the UDP port for HTTP/3 |
| `--data DIR` | `parley-data` | Journal, uploaded media, generated certificate |
| `--web DIR` | source `web/` | Browser client files |
| `--certificate FILE`, `--private-key FILE` | generated | PEM chain and key |
| `--http3` | off | Also serve HTTP/3 and advertise it with `Alt-Svc` |

Press Ctrl-C to stop. Shutdown cancels every connection and writes any
journal lines that were still queued.

To build against an installed eventloop package instead of this checkout,
configure with `-DEVENTLOOP_SOURCE_DIR=`.

## How it uses eventloop

| Need | Library feature |
| --- | --- |
| Pages, scripts, styles | `https_server` static files from `--web` (ETag, ranges, open-file cache) |
| JSON API | `http::router` handlers (`api.cc`) |
| Realtime | `request::async_accept_websocket()` (RFC 8441 Extended CONNECT) with `ws::web_socket` |
| Realtime fallback | Server-sent events written with `response::async_write` |
| Uploads | `request::async_read_body` into `async_openat` and `async_write_at` |
| Media | `response::async_send_file` with single-range support |
| Password hashing | `run_blocking` on the loop's worker threads |
| HTTP/3 | `http3_server` sharing the same router |
| Journal | `async_write_at` from one writer coroutine woken by `wakeup` |

Every realtime connection is a `client` in the `hub` (`hub.h`) with a bounded
queue of encoded events. A WebSocket connection runs a reader and a writer
under `when_all`; an event stream runs a writer only. Writers sleep on an
`eventloop::wakeup`: a sender queues events and calls `notify()`, and the loop
resumes the writer after the sender returns, so fan-out never runs a
recipient's writer on the sender's stack. Connection loss and shutdown cancel
the wait.

## Realtime transport

The client opens `wss://host/api/ws`. Chromium and Firefox send it as
Extended CONNECT on the page's HTTP/2 connection. If the WebSocket is
refused while ordinary requests work (an HTTP/1.1 upgrade attempt is
answered with 426, and browsers don't offer WebSockets over HTTP/3), the
client switches to `EventSource('/api/events')` and posts commands to
`/api/command`. Events and commands are the same JSON in both modes:

| Client command | Effect |
| --- | --- |
| `{"t":"send","conv","text","media","duration","reply_to","client_id"}` | Store and fan out a message |
| `{"t":"delivered"\|"read","conv","upto"}` | Advance this user's receipt |
| `{"t":"typing","conv","recording"}` | Forward a typing or recording indicator |

Server events have `t` set to `message`, `receipt`, `typing`, `presence`,
`user`, `conversation`, `error`, or `ping`. After every (re)connect the client
reloads `/api/bootstrap` and the newest page of each open conversation, so a
missed event never leaves it stale.

## Bounds

| Resource | Limit | When exceeded |
| --- | --- | --- |
| Users | 4096 | Registration fails |
| Conversations | 65536 | Creation fails |
| Group members | 256 | Creation fails |
| Message text | 4096 bytes | Command error |
| JSON request body | 64 KiB | 400 |
| Upload | 16 MiB | 413 |
| Realtime connections | 4096 total, 16 per user | 503, or the WebSocket is reset |
| Queued events per connection | 512 | The connection closes; the client reconnects and reloads |
| Messages kept per conversation | 20000 | Oldest leave history |
| Unwritten journal | 16 MiB | Changes fail with "storage busy" |
| WebSocket message | 64 KiB | Connection closes |

Fan-out never blocks on a slow recipient. On HTTP/2, a WebSocket holds one of
the connection's eight 16 KiB body slots for its lifetime.

## Security notes

- Passwords: PBKDF2-HMAC-SHA256 with 200,000 iterations and a random salt.
  Only the SHA-256 of each session token is stored. Unknown usernames
  still pay for a hash.
- State-changing requests and WebSockets require a same-origin `Origin`
  header when one is sent, on top of `SameSite=Strict` cookies.
- Media is readable by its uploader and the members of the conversation it
  was sent to. Names are random 128-bit IDs. Images and audio are served
  inline from a fixed type list, and everything else as an attachment. All
  media carries `nosniff` and a sandboxing Content-Security-Policy.
- The client builds all markup with DOM APIs, never from message text.

## Known limitations

- QUIC connections that disappear without a CONNECTION_CLOSE stay attached
  until the QUIC idle timeout (about 30 seconds) closes them.
- Chromium uses HTTP/3 with a self-signed certificate only if its key is
  pinned:

  ```sh
  spki=$(openssl x509 -in parley-data/certificate.pem -pubkey -noout |
         openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64)
  chromium --origin-to-force-quic-on=localhost:8443 \
           --ignore-certificate-errors-spki-list="$spki" \
           --host-resolver-rules="MAP localhost 127.0.0.1"
  ```

  Over HTTP/3, Chromium uses the event-stream fallback.
- The journal is not fsynced, so a power loss can drop the latest changes. It
  is never compacted.

## Smoke test

```sh
examples/parley/smoke.sh ./build-parley/parley
```

The script uses curl over HTTP/2 to cover accounts, conversations, events,
receipts, uploads, ranged media, access control, graceful shutdown, and
journal replay.
