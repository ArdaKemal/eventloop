# Security policy

## Supported versions

Before 1.0, only the latest release and `main` receive security fixes.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub: open the repository's
**Security** tab and choose **Report a vulnerability**. Do not open a public
issue for a suspected vulnerability.

Include the affected version or commit, the platform, and a reproducer if you
have one, such as a request, packet capture, or fuzzer input. You should get a
reply within a week. Fixes are released with a changelog entry that credits the
reporter unless they ask otherwise.

## Scope

The parsers and protocol state machines that read peer input (HTTP/1.1,
HTTP/2 and HPACK, HTTP/3 and QPACK, QUIC, WebSocket, TLS integration) and the
static-file server's path handling are in scope. The examples under
`examples/` are demonstrations, not hardened servers.
