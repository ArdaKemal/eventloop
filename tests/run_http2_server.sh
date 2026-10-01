#!/usr/bin/env bash
set -euo pipefail

server=$1
openssl=$2
curl=$3

if ! "$curl" --version | grep -q 'HTTP2'; then
    echo 'curl lacks HTTP/2 support; skipping HTTP/2 server integration test' >&2
    exit 0
fi

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/eventloop-http2-server.XXXXXX")
server_pid=''
cleanup() {
    if [[ -n $server_pid ]] && kill -0 "$server_pid" 2>/dev/null; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    rm -rf "$work_dir"
}
trap cleanup EXIT INT TERM

mkdir -p "$work_dir/www/list" "$work_dir/www/empty"
printf 'HTTP/2 fixture\n' > "$work_dir/www/file.txt"
printf '<h1>index</h1>\n' > "$work_dir/www/index.html"
printf 'listed' > "$work_dir/www/list/a&b.txt"
printf 'outside root' > "$work_dir/secret.txt"
ln -s "$work_dir/secret.txt" "$work_dir/www/leak.txt"
head -c 1048576 /dev/zero | tr '\0' 'h' > "$work_dir/www/large.bin"

"$openssl" req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj /CN=localhost -keyout "$work_dir/key.pem" \
    -out "$work_dir/cert.pem" > /dev/null 2>&1

http_port=$((20000 + $$ % 10000))
https_port=$((http_port + 10000))
"$server" --root "$work_dir/www" --certificate "$work_dir/cert.pem" \
    --private-key "$work_dir/key.pem" --hostname localhost \
    --http-port "$http_port" --https-port "$https_port" \
    --directory-listing > "$work_dir/server.log" 2>&1 &
server_pid=$!

base="https://localhost:$https_port"
fail() {
    echo "HTTP/2 server integration failure: $*" >&2
    sed -n '1,120p' "$work_dir/server.log" >&2
    exit 1
}

# Every request requires ALPN h2, including the readiness probe.
request() {
    local expected=$1
    local output=$2
    shift 2
    local result
    result=$("$curl" --silent --show-error --insecure --http2 \
        --output "$output" --write-out '%{http_version} %{http_code}' \
        "$@") || fail "curl failed: $*"
    [[ $result == "2 $expected" ]] || fail "expected HTTP/2 $expected, got $result: $*"
}

ready=false
for _ in {1..100}; do
    if "$curl" --silent --insecure --http2 --output /dev/null \
        --write-out '%{http_version} %{http_code}' "$base/file.txt" \
        2>/dev/null | grep -qx '2 200'; then
        ready=true
        break
    fi
    sleep 0.05
done
[[ $ready == true ]] || fail 'server did not start'

request 200 "$work_dir/file.out" "$base/file.txt"
cmp "$work_dir/www/file.txt" "$work_dir/file.out"
request 200 "$work_dir/index.out" "$base/"
cmp "$work_dir/www/index.html" "$work_dir/index.out"

request 200 "$work_dir/head.out" --head --dump-header "$work_dir/head.headers" \
    "$base/large.bin"
grep -iq '^content-length: 1048576' "$work_dir/head.headers"
request 204 "$work_dir/options.out" --request OPTIONS \
    --dump-header "$work_dir/options.headers" "$base/file.txt"
grep -iq '^allow: GET, HEAD, OPTIONS' "$work_dir/options.headers"
request 405 "$work_dir/post.out" --request POST \
    --dump-header "$work_dir/post.headers" "$base/file.txt"
grep -iq '^allow: GET, HEAD, OPTIONS' "$work_dir/post.headers"
request 404 "$work_dir/missing.out" "$base/missing.txt"

request 308 "$work_dir/redirect.out" --dump-header "$work_dir/redirect.headers" \
    "$base/list?x=1"
grep -iq '^location: /list/?x=1' "$work_dir/redirect.headers"
request 200 "$work_dir/list.out" "$base/list/"
grep -Fq 'href="a%26b.txt"' "$work_dir/list.out"
grep -Fq 'a&amp;b.txt' "$work_dir/list.out"
request 200 "$work_dir/escaped.out" "$base/list/a%26b.txt"
cmp "$work_dir/www/list/a&b.txt" "$work_dir/escaped.out"

request 400 "$work_dir/traversal.out" --path-as-is "$base/%2e%2e/secret.txt"
# A malformed target is rejected at the HTTP/2 stream boundary. curl reports
# the stream reset as error 92 rather than receiving an HTTP response.
if "$curl" --silent --insecure --http2 --output "$work_dir/bad-escape.out" \
    "$base/%ZZ"; then
    fail 'malformed target unexpectedly succeeded'
else
    [[ $? == 92 ]] || fail 'malformed target failed for an unexpected reason'
fi
request 404 "$work_dir/symlink.out" "$base/leak.txt"
request 414 "$work_dir/long.out" "$base/$(printf 'a%.0s' {1..4100})"

# This needs repeated WINDOW_UPDATE frames in both connection and stream scope.
request 200 "$work_dir/large.out" "$base/large.bin"
cmp "$work_dir/www/large.bin" "$work_dir/large.out"

# Ask curl to open several streams on one h2 connection. Check actual stream
# assignment in the trace, then compare every body and the large transfer.
parallel_args=()
for index in {1..6}; do
    parallel_args+=(--output "$work_dir/parallel-$index.out" \
        "$base/file.txt?request=$index")
done
parallel_args+=(--output "$work_dir/parallel-large.out" "$base/large.bin")
"$curl" --silent --show-error --insecure --http2 --parallel \
    --parallel-max 8 --trace-ascii "$work_dir/parallel.trace" \
    "${parallel_args[@]}" || fail 'parallel transfer failed'
for index in {1..6}; do
    cmp "$work_dir/www/file.txt" "$work_dir/parallel-$index.out"
done
cmp "$work_dir/www/large.bin" "$work_dir/parallel-large.out"
grep -Eq 'Multiplexed connection|Using Stream ID' "$work_dir/parallel.trace" || \
    fail 'curl did not report multiplexed HTTP/2 streams'

echo 'HTTP/2 server integration: ALPN, methods, paths, security, flow control, and parallel streams passed'
