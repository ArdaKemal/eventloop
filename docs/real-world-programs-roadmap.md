# Wayfarer and Stonegate milestones

Wayfarer and Stonegate are small, concrete callers of eventloop. Their goal is
to cover useful everyday HTTP work while keeping limits visible. They are not
planned as complete replacements for curl, nginx, or lighttpd.

## Delivery rule

Each milestone is implemented in its own scoped worktree. After implementation,
an independent `gpt-6-luna` high subagent runs the milestone's acceptance
checks and reports commands, results, and failures. Any failed check is fixed
and rerun before committing. Each passing milestone gets its own commit; library
changes are committed before an example change that depends on them. Keep
unrelated work out of that commit.

Milestones stay within the public API where possible. If a milestone requires a
new library API or a cross-cutting library fix, first document the caller,
ownership, bounds, cancellation behavior, and affected platforms in the API
contract. Preserve current explicit deferrals: proxying, cookies, authentication,
compression, resumable or recursive downloads, and broad non-HTTP protocol
support are not near-term Wayfarer goals.

## Wayfarer

Committed baseline: `2c6dbd9` adds the HTTP client example after `d176bd4`, the
outbound HTTP/2 API. Current behavior includes HTTP/1.1, bounded HTTP/2 upload
and response streaming, HTTP/2 redirects, and a deliberately narrow HTTP/3
GET client built on public QUIC APIs.

### W1 — Safe output and HTTP failure status

- Write `-o` responses to a sibling temporary file and replace the target only
  after a complete successful transfer. Keep stdout streaming and document that
  stdout can contain a partial response after a failure.
- Add `--fail` with a documented nonzero exit on HTTP 4xx/5xx while preserving
  the current default behavior for HTTP error statuses.
- Check binary output for HTTP/1.1 Content-Length, chunked and close-delimited
  bodies, HTTP/2 streamed DATA, and bounded HTTP/3 DATA. Check timeout,
  truncation, malformed response, and file-write errors; existing destination
  files must survive failed downloads and temporary files must be removed.

### W2 — HTTP/1.1 redirect support

- Bring `-L` to HTTP/1.1 with relative and absolute Location values, a ten-hop
  cap, method rewriting for 301/302/303, method/body preservation for 307/308,
  and removal of Authorization, Cookie, and Proxy-Authorization on origin
  changes.
- Keep redirect bodies out of the final output; with `-i`, preserve response
  header ordering. Reject HTTPS-to-HTTP downgrade and report missing Location
  or redirect loops clearly.
- Compare HTTP/1.1 results with the current HTTP/2 behavior for GET, HEAD, POST,
  and file-backed uploads. Test each redirect status and policy failure.

### W3 — Bounded HTTP/3 response parity

- Add HTTP/3 HEAD and response header output, then HTTP/3 redirect following
  within the existing bounded static-QPACK design.
- Support only explicitly tested QPACK forms. Keep dynamic QPACK, server push,
  uploads, and connection reuse out of scope until there is a concrete caller
  and a separately bounded design.
- Test QUIC v1 and v2 with status, headers, split DATA frames, trailers,
  redirects, timeouts, oversized inputs, malformed frames, and unsupported
  QPACK encodings.

### W4 — Download-focused CLI ergonomics

- Add `--head`/`-I` and `--remote-name`/`-O` with a sanitized URL basename,
  collision policy, and binary-safe output. Consider multiple URLs only after
  output naming and per-transfer error behavior are defined.
- Keep progress or transfer metadata on stderr so stdout remains suitable for
  pipelines. Help text, exit codes, and README support tables must match actual
  behavior.
- Test filenames with encoded paths, queries, empty names, traversal-like
  values, existing files, all available HTTP versions, and clean stdout.

## Stonegate

Stonegate's current example serves a document root over plain HTTP/1.1, TLS
HTTP/1.1 and HTTP/2, and optional HTTP/3. It supports index files and directory
listing on the HTTP/1.1 and HTTP/2 built-in servers. The repeated HTTP/3 OPTIONS
timeout is the first reliability gate; its trace currently points to a timer
wakeup issue in the event loop.

### S1 — Reliable HTTP/3 request completion

- Fix the event-loop timer wakeup issue with the smallest supported change and
  add a regression check for the timer behavior.
- Require repeated fresh HTTP/3 connections to complete GET, HEAD, and OPTIONS,
  including GET after OPTIONS. Verify the 204 response and `Allow` semantics.
- Recheck plain HTTP/1.1, TLS HTTP/1.1, TLS HTTP/2, redirects, traversal and
  symlink rejection, listener shutdown, and port reuse. Remove all temporary
  tracing before the independent test pass.

### S2 — Validated server configuration file

- Add a small documented configuration file for the existing settings: bind
  address, document root, listener ports, TLS files, HTTP mode, HTTP/2, HTTP/3,
  directory listing, and shutdown deadline. Preserve command-line overrides and
  define their precedence.
- Reject duplicate, unknown, malformed, and conflicting settings before
  opening listeners. Keep secrets out of logs and error messages.
- Test defaults, CLI overrides, relative file paths, invalid values, missing
  credentials, port conflicts, and equivalent CLI-only versus config-driven
  launches.

### S3 — Conditional and range file responses

- Add static-file validators (`ETag` and `Last-Modified`), conditional
  `If-None-Match`/`If-Modified-Since` responses, and single byte ranges with
  correct 206 and 416 responses.
- First review the built-in HTTP/1.1, HTTP/2, and HTTP/3 API boundaries and
  capacity behavior; this milestone needs library implementation if the current
  APIs do not expose the required behavior.
- Test GET and HEAD across all enabled protocols, including matching and stale
  validators, first/last/open-ended ranges, unsatisfiable ranges, empty files,
  and symlink/traversal cases.

### S4 — HTTP/3 directory-listing parity

- Add bounded HTTP/3 directory listings consistent with the existing HTTP/1.1
  and HTTP/2 behavior, including index-file preference, safe HTML escaping,
  hidden-file policy, and stable sorting.
- Define limits for entry count and generated response bytes, and return a
  useful error when a listing exceeds them. Preserve the component-by-component
  `O_NOFOLLOW` path walk.
- Compare listing output across HTTP/1.1, HTTP/2, and HTTP/3; test unusual
  filenames, hidden files, index files, large directories, and symlinks.

Access-log callbacks, virtual-host routing, reverse proxying, dynamic modules,
and live configuration reload remain future work. They need public API designs
and concrete callers before they enter a milestone.

## Reference patterns

These projects are feature references, not compatibility targets:

- [curl man page](https://curl.se/docs/manpage.html) documents protocol
  selection, writing response bodies to stdout or files, and redirect method
  behavior.
- [nginx HTTP core](https://nginx.org/en/docs/http/ngx_http_core_module.html)
  documents document roots, index files, and request-location behavior;
  [nginx access logging](https://nginx.org/en/docs/http/ngx_http_log_module.html)
  shows the separate operational role of request logs.
- [lighttpd static files](https://redmine.lighttpd.net/projects/lighttpd/wiki/Mod_staticfile)
  documents validators and static-file handling, while
  [directory listings](https://redmine.lighttpd.net/projects/lighttpd/wiki/Mod_dirlisting)
  documents index fallback, sorting, and hidden-file controls.
