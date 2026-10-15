# WebTransport over HTTP/3 echo server

Build and run the server with a PEM certificate and key for `localhost`:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target webtransport_echo_server
./build/webtransport_echo_server 4433 cert.pem key.pem
```

The server listens on UDP port 4433 and serves WebTransport sessions at the
Extended CONNECT route `/echo` (`:protocol webtransport-h3`). A session accepts
the protocol `echo/1` when the client offers it in `WT-Available-Protocols`.
On each session the server:

- echoes every bidirectional stream back to the client;
- reads each client uni stream and sends its bytes back on a new server uni stream;
- echoes every datagram, up to the session's `max_datagram_size()`.

Run the example's test, which starts the same routes and checks one echo of each kind
with the test client:

```sh
ctest --test-dir build -R webtransport_example --output-on-failure
```

The HTTP/3 protocol contract is in [HTTP/3](../docs/http3.md).
