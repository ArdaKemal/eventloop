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
    "https://localhost:$https_port/files/" > "$work_dir/listing.out"
grep -Fq 'href="a%26b.txt"' "$work_dir/listing.out"
grep -Fq 'a&amp;b.txt' "$work_dir/listing.out"

"$curl" --silent --dump-header "$work_dir/redirect.headers" \
    --output /dev/null "http://localhost:$http_port/file.txt?download=1"
grep -Fq 'HTTP/1.1 308 Permanent Redirect' "$work_dir/redirect.headers"
grep -Fq "Location: https://localhost:$https_port/file.txt?download=1" \
    "$work_dir/redirect.headers"
