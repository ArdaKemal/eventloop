#!/usr/bin/env bash
# Runs the h2spec conformance suite (RFC 9113 and RFC 7541) against the TLS
# example server. Every test must pass: none may fail or be skipped.
set -euo pipefail

server=$1
openssl=$2
h2spec=$3

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/eventloop-h2spec.XXXXXX")
server_pid=''
cleanup() {
    if [[ -n "$server_pid" ]] && kill -0 "$server_pid" 2>/dev/null; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    rm -rf "$work_dir"
}
trap cleanup EXIT INT TERM

mkdir -p "$work_dir/www"
# h2spec skips its window-size test unless the response at / exceeds the
# default flow-control window.
head -c 300000 /dev/zero | tr '\0' 'x' > "$work_dir/www/index.html"

"$openssl" req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj /CN=localhost \
    -addext subjectAltName=DNS:localhost,IP:127.0.0.1 \
    -keyout "$work_dir/key.pem" -out "$work_dir/cert.pem" \
    > /dev/null 2>&1

http_port=$((20000 + $$ % 10000))
https_port=$((http_port + 10000))

"$server" --root "$work_dir/www" \
    --certificate "$work_dir/cert.pem" --private-key "$work_dir/key.pem" \
    --hostname localhost --http-port "$http_port" --https-port "$https_port" \
    > "$work_dir/server.log" 2>&1 &
server_pid=$!
sleep 0.5

"$h2spec" -h localhost -p "$https_port" -t -k -S > "$work_dir/h2spec.log" 2>&1 || true
summary=$(grep -E '^[0-9]+ tests,' "$work_dir/h2spec.log" || true)
echo "$summary"
if [[ "$summary" != *' 0 skipped, 0 failed' ]]; then
    grep -E '^\s+×' -A6 "$work_dir/h2spec.log" >&2 || true
    exit 1
fi
