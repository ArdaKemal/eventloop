# Lantern

Lantern is a YouTube-style video site built on eventloop's public API. The
browser client is plain HTML, CSS, and JavaScript; the server is one event
loop that serves it over TLS HTTP/1.1 and HTTP/2, and optionally HTTP/3 and
cleartext HTTP/1.1.

- Home feed, search, channel pages, and a watch page with "up next".
- Uploads of up to 4 GiB in 8 MiB chunks. A lost connection, a server
  restart, or a page reload resumes from the last byte stored.
- The browser reads each video's length and draws its thumbnail before
  uploading, so the server needs no media tools. Videos are served as
  uploaded, with no transcoding.
- Playback with byte ranges, so the viewer can seek. The watch page shows
  which HTTP version carried the video.
- View counts and the catalog are kept in a tab-separated journal and
  replayed on start.

Lantern has no accounts: anyone who can reach it can upload. It binds to
loopback by default.

## Build and run

```sh
cmake -S examples/lantern -B build-lantern -DCMAKE_BUILD_TYPE=Release
cmake --build build-lantern --target lantern
./build-lantern/lantern            # https://localhost:8443/
```

On first start, Lantern writes a self-signed certificate for `localhost`,
`127.0.0.1`, and `::1` into the data directory (`lantern-data/` by default).
Your browser shows a certificate warning for it; pass `--certificate` and
`--private-key` to use your own.

| Option | Default | Meaning |
| --- | --- | --- |
| `--bind ADDRESS` | `127.0.0.1` | Numeric IPv4 or IPv6 listen address |
| `--port PORT` | `8443` | TLS port, and the UDP port for HTTP/3 |
| `--http-port PORT` | off | Also serve cleartext HTTP/1.1 |
| `--data DIR` | `lantern-data` | Journal, videos, thumbnails, generated certificate |
| `--web DIR` | source `web/` | Browser client files |
| `--certificate FILE`, `--private-key FILE` | generated | PEM chain and key |
| `--max-video MIB` | `4096` | Largest accepted video |
| `--http3` | off | Also serve HTTP/3 and advertise it with `Alt-Svc` |

Press Ctrl-C to stop. Shutdown cancels every request; an interrupted upload
resumes from the bytes already on disk.

To build against an installed eventloop package instead of this checkout,
configure with `-DEVENTLOOP_SOURCE_DIR=`.

## How it uses eventloop

| Need | Library feature |
| --- | --- |
| Pages, scripts, styles | Static files from `--web` with the open-file cache |
| JSON API | `http::router` handlers (`api.cc`) |
| Upload chunks | `request::async_read_body` into a 256 KiB buffer, then `async_write_at` |
| Playback | `response::async_send_file` with single ranges. TLS uses kTLS `sendfile` when the connection has it, cleartext HTTP/1.1 uses `sendfile` for ranges from byte 0, and other cases use bounded buffered reads |
| Journal | `async_write_at` at offsets reserved per record, so concurrent changes need no queue |
| HTTP/3 | `http3_server` sharing the same router |

## Upload protocol

| Request | Effect |
| --- | --- |
| `POST /api/uploads` (form: `size`, `type`, `duration`, `title`, `description`, `channel`) | Create an upload; returns `id`, `received`, `chunk` |
| `PUT /api/uploads/ID?offset=N` | Store the body at `N`; `N` must equal `received`, or the answer is 409 with the current state |
| `GET /api/uploads/ID` | Report `received`, to resume from |
| `PUT /api/uploads/ID/thumbnail` | Store a JPEG thumbnail |
| `POST /api/uploads/ID/publish` | Publish once every byte arrived |
| `DELETE /api/uploads/ID` | Discard an unfinished upload |

Bytes that arrived before a connection broke are kept, so the client resumes
from `received` and never resends them. Only one request writes an upload at
a time; a second one gets 409. The client keeps unfinished uploads in
`localStorage`, and choosing the same file again resumes it.

## Bounds

| Resource | Limit | When exceeded |
| --- | --- | --- |
| Video size | `--max-video` | 413 when the upload is created |
| Request body | 8 MiB, one chunk | 413 |
| Thumbnail | 512 KiB JPEG | 400 |
| Title, channel, description | 100, 50, 5000 bytes | 400 |
| Listing | 60 newest matches | Older matches are not listed |
| HTTP/3 connections | 64 | New connections are refused |

## Stress test

`stress.py` starts Lantern with a fresh data directory, uploads a video over
every transport, then runs many viewers at once. Each viewer requests random
byte ranges over cleartext HTTP/1.1, TLS HTTP/1.1, HTTP/2, and HTTP/3, and
drops half of them in the middle of the body, as a browser does when the
viewer seeks. Two more uploads run meanwhile. Completed ranges must match the
file byte for byte, and Ctrl-C must stop the server cleanly.

```sh
python3 examples/lantern/stress.py build-lantern/lantern --viewers 48 --requests 60
LANTERN_WRAPPER="valgrind --error-exitcode=99" \
    python3 examples/lantern/stress.py build-lantern/lantern --viewers 4 --requests 30
```

It needs curl built with HTTP/3 support. This test found that one HTTP/3 client
closing before the server accepted its connection stopped HTTP/3 for everyone,
fixed in the library alongside this example.
