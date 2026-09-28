#!/usr/bin/env bash
set -euo pipefail

server=$1
openssl=$2
curl=$3

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/eventloop-http-server.XXXXXX")
server_pid=''
cleanup() {
    if [[ -n "$server_pid" ]] && kill -0 "$server_pid" 2>/dev/null; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    rm -rf "$work_dir"
}
trap cleanup EXIT INT TERM

mkdir -p "$work_dir/www/files"
printf 'secure static file' > "$work_dir/www/file.txt"
printf '<h1>home</h1>' > "$work_dir/www/index.html"
printf 'directory entry' > "$work_dir/www/files/a&b.txt"
head -c 16384 /dev/zero | tr '\0' 'x' > "$work_dir/www/large.bin"
head -c 262144 /dev/zero | tr '\0' 'h' > "$work_dir/www/h2-large.bin"

"$openssl" req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj /CN=localhost \
    -keyout "$work_dir/key.pem" -out "$work_dir/cert.pem" \
    > /dev/null 2>&1

http_port=$((20000 + $$ % 10000))
https_port=$((http_port + 10000))

"$server" \
    --root "$work_dir/www" \
    --certificate "$work_dir/cert.pem" \
    --private-key "$work_dir/key.pem" \
    --hostname localhost \
    --http-port "$http_port" \
    --https-port "$https_port" \
    --directory-listing \
    > "$work_dir/server.log" 2>&1 &
server_pid=$!

for _ in {1..100}; do
    if "$curl" --silent --insecure --fail --http1.1 \
        "https://localhost:$https_port/file.txt" > "$work_dir/file.out"; then
        break
    fi
    sleep 0.05
done

if [[ $(<"$work_dir/file.out") != 'secure static file' ]]; then
    sed -n '1,120p' "$work_dir/server.log" >&2
    exit 1
fi

"$curl" --silent --insecure --fail --http1.1 \
    "https://localhost:$https_port/" > "$work_dir/index.out"
[[ $(<"$work_dir/index.out") == '<h1>home</h1>' ]]

"$curl" --silent --insecure --fail --http1.1 \
    "https://localhost:$https_port/large.bin" > "$work_dir/large-tls.out"
cmp "$work_dir/www/large.bin" "$work_dir/large-tls.out"

"$curl" --silent --insecure --fail --http1.1 \
    "https://localhost:$https_port/files/" > "$work_dir/listing.out"
grep -Fq 'href="a%26b.txt"' "$work_dir/listing.out"
grep -Fq 'a&amp;b.txt' "$work_dir/listing.out"

if "$curl" --version | grep -q 'HTTP2'; then
    h2_version=$("$curl" --silent --insecure --fail --http2 \
        --output "$work_dir/h2-file.out" --write-out '%{http_version}' \
        "https://localhost:$https_port/file.txt")
    [[ $h2_version == 2 ]]
    [[ $(<"$work_dir/h2-file.out") == 'secure static file' ]]

    h2_head=$("$curl" --silent --insecure --fail --http2 --head \
        --output /dev/null --write-out '%{http_version} %{http_code}' \
        "https://localhost:$https_port/file.txt")
    [[ $h2_head == '2 200' ]]

    h2_options=$("$curl" --silent --insecure --fail --http2 \
        --request OPTIONS --output /dev/null \
        --write-out '%{http_version} %{http_code}' \
        "https://localhost:$https_port/file.txt")
    [[ $h2_options == '2 204' ]]

    h2_large_version=$("$curl" --silent --insecure --fail --http2 \
        --output "$work_dir/h2-large.out" --write-out '%{http_version}' \
        "https://localhost:$https_port/h2-large.bin")
    [[ $h2_large_version == 2 ]]
    cmp "$work_dir/www/h2-large.bin" "$work_dir/h2-large.out"

    "$curl" --silent --insecure --fail --http2 --parallel \
        --parallel-max-host 1 \
        --output "$work_dir/h2-parallel-file.out" \
        "https://localhost:$https_port/file.txt" \
        --output "$work_dir/h2-parallel-index.out" \
        "https://localhost:$https_port/index.html"
    [[ $(<"$work_dir/h2-parallel-file.out") == 'secure static file' ]]
    [[ $(<"$work_dir/h2-parallel-index.out") == '<h1>home</h1>' ]]
else
    echo 'curl lacks HTTP/2 support; skipping HTTP/2 server checks' >&2
fi

"$curl" --silent --dump-header "$work_dir/redirect.headers" \
    --output /dev/null "http://localhost:$http_port/file.txt?download=1"
grep -Fq 'HTTP/1.1 308 Permanent Redirect' "$work_dir/redirect.headers"
grep -Fq "Location: https://localhost:$https_port/file.txt?download=1" \
    "$work_dir/redirect.headers"

kill "$server_pid"
wait "$server_pid" 2>/dev/null || true
server_pid=''

plain_port=$((http_port + 1))
"$server" \
    --root "$work_dir/www" \
    --http-only \
    --http-port "$plain_port" \
    --directory-listing \
    > "$work_dir/http-only.log" 2>&1 &
server_pid=$!

for _ in {1..100}; do
    if "$curl" --silent --fail --http1.1 \
        "http://localhost:$plain_port/file.txt" > "$work_dir/plain.out"; then
        break
    fi
    sleep 0.05
done

if [[ $(<"$work_dir/plain.out") != 'secure static file' ]]; then
    sed -n '1,120p' "$work_dir/http-only.log" >&2
    exit 1
fi

"$curl" --silent --fail --http1.1 \
    "http://localhost:$plain_port/large.bin" > "$work_dir/large-http.out"
cmp "$work_dir/www/large.bin" "$work_dir/large-http.out"
