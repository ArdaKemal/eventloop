# Outbound HTTP/2 interoperability probe

`examples/probe_http2_client.py` runs the system `curl` HTTP/2 client against
ten public HTTPS URLs. It is an external interoperability probe, not an
`eventloop` HTTP/2 client example: the library's current outbound HTTP example
sends HTTP/1.1, and its HTTP/2 implementation serves inbound requests.

Prerequisites: Python 3 and a `curl` build with the `HTTP2` feature (`curl
--version`). Run from the repository root:

```sh
python3 examples/probe_http2_client.py
python3 examples/probe_http2_client.py --url https://example.com/ --url https://www.google.com/
```

Each URL has a five second connect timeout and a fifteen second total timeout
by default. `--connect-timeout` and `--timeout` override these values. Up to
four requests run concurrently; results print in input order. The command
exits successfully only when every URL returns a 2xx/3xx status and curl
reports HTTP/2 for the final response. Redirects remain HTTPS. Public sites
may change behavior or be unreachable, so a failed probe needs inspection.

On 2026-10-01, the ten default URLs all returned HTTP/2 and status 200 with
the host's curl 8.14.1 (nghttp2 1.64.0): Google, Cloudflare, Wikipedia,
GitHub, Python, Mozilla, Apple, Microsoft, Rust, and kernel.org. The first
attempt in the restricted sandbox could not resolve any host; the network
enabled run passed 10/10.
