# Event loop

A small C++23 event loop with an epoll backend and reusable asynchronous TCP
transport classes. The echo protocol is implemented separately as a demo.

## Layout

```text
include/eventloop/  Public event loop and TCP transport API
src/                Platform-independent implementations
src/linux/          Private Linux epoll backend
examples/           Programs built on top of the library
tests/              Plain/TLS transport integration coverage
```

```sh
cmake -S . -B build
cmake --build build
./build/tcp_echo 7000
```

The server listens on loopback. Stop it with `Ctrl-C`.

For the TLS echo example, provide a PEM certificate chain and private key:

```sh
./build/tls_echo certificate.pem private-key.pem 7443
```

Run the HTTP/1.1 static-file server with a document root and TLS certificate:

```sh
./build/http_server \
    --root ./public \
    --certificate certificate-chain.pem \
    --private-key private-key.pem \
    --hostname example.com \
    --http-port 80 \
    --https-port 443
```

The HTTP listener redirects requests to HTTPS. The HTTPS listener serves files
and uses `index.html` for directories. Pass `--directory-listing` to generate a
listing when a directory has no index file. Run `http_server --help` for all
options.

To serve plain HTTP without TLS or a redirect listener, certificate files are
not required:

```sh
./build/http_server --root ./public --http-only --http-port 8080
```

The HTTP parser and request/response path use fixed-capacity buffers. Requests
larger than those limits receive an appropriate 4xx response instead of
growing buffers dynamically.

Run the transport tests with:

```sh
ctest --test-dir build --output-on-failure
```

## HTTP throughput comparison

On Debian/Ubuntu, install `wrk`, `nginx`, and `lighttpd`, then run:

```sh
./benchmark/http-throughput.sh
```

The harness builds the HTTP example in `Release` mode if necessary, generates
one static payload, and runs each server on loopback with one worker and the
same `wrk` keep-alive workload. It warms each server before reporting `wrk`'s
requests/sec, transfer/sec, and latency. Defaults are a 4 KiB payload, 128
connections, one `wrk` thread, and a 15-second measurement. Override them for
additional profiles, for example:

```sh
FILE_SIZE=1024 CONNECTIONS=256 DURATION=30s ./benchmark/http-throughput.sh
```

Use `SERVER=eventloop`, `SERVER=nginx`, or `SERVER=lighttpd` to repeat one
participant while diagnosing a result.

This is a local HTTP/1.1 static-file benchmark, not a production tuning guide.
Plain HTTP file responses use Linux `sendfile`; HTTPS responses pass through
Botan in user space. Plain HTTP files smaller than 11 KiB use the buffered path;
larger files use `sendfile`. Treat the comparison as end-to-end baseline data
and record the command, CPU, and package versions with any result.
