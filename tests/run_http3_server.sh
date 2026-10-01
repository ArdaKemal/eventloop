#!/usr/bin/env bash
set -euo pipefail

server=$1
openssl=$2
curl=$3

if ! "$curl" --version | grep -q HTTP3; then
    echo 'curl lacks HTTP/3; HTTP/3 server interoperability cannot run' >&2
    exit 1
fi

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/eventloop-http3-server.XXXXXX")
server_pid=''
cleanup() {
    status=$?
    trap - EXIT INT TERM
    if [[ -n "$server_pid" ]] && kill -0 "$server_pid" 2>/dev/null; then
        kill -INT "$server_pid" 2>/dev/null || true
    fi
    if [[ -n "$server_pid" ]]; then
        if wait "$server_pid"; then
            echo 'HTTP/3 server stopped cleanly'
        else
            server_status=$?
            echo "HTTP/3 server exited with status $server_status" >&2
            status=1
        fi
    fi
    if (( status != 0 )); then
        echo 'HTTP/3 server regression failed; server log:' >&2
        cat "$work_dir/server.log" >&2 || true
    fi
    rm -rf "$work_dir"
    exit "$status"
}
trap cleanup EXIT INT TERM

mkdir -p "$work_dir/www"
printf 'http3 slot reuse\n' > "$work_dir/www/index.html"
"$openssl" req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj /CN=localhost -keyout "$work_dir/key.pem" \
    -out "$work_dir/cert.pem" > /dev/null 2>&1

port=$((40000 + $$ % 20000))
"$server" "$port" "$work_dir/www" "$work_dir/cert.pem" "$work_dir/key.pem" \
    > "$work_dir/server.log" 2>&1 &
server_pid=$!

ready=false
for _ in {1..100}; do
    if "$curl" --http3-only --silent --insecure --max-time 1 \
        --output "$work_dir/start.out" --write-out '%{http_code}' \
        "https://127.0.0.1:$port/" > "$work_dir/start.status"; then
        if [[ $(<"$work_dir/start.status") == 200 ]]; then ready=true; break; fi
    fi
    sleep 0.05
done
if [[ $ready != true ]]; then
    echo 'HTTP/3 server did not become ready after 100 attempts' >&2
    exit 1
fi
echo 'HTTP/3 server ready: GET 200'

# Separate curl processes force slot retirement and reuse. A retired handle's
# later close must not mark the next accepted connection as closing.
for _ in {1..3}; do
    get=$(
        "$curl" --http3-only --silent --insecure --max-time 4 \
            --output "$work_dir/get.out" --write-out '%{http_code} %{http_version}' \
            "https://127.0.0.1:$port/")
    [[ $get == '200 3' ]]
    cmp "$work_dir/www/index.html" "$work_dir/get.out"

    head=$(
        "$curl" --http3-only --silent --insecure --head --max-time 4 \
            --output "$work_dir/head.out" --write-out '%{http_code} %{http_version}' \
            "https://127.0.0.1:$port/")
    [[ $head == '200 3' ]]
    grep -qi '^content-length: 17' "$work_dir/head.out"

    options=$(
        "$curl" --http3-only --silent --insecure --head -X OPTIONS \
            --max-time 4 --output "$work_dir/options.out" \
            --write-out '%{http_code} %{http_version}' \
            "https://127.0.0.1:$port/")
    [[ $options == '204 3' ]]
    grep -qi '^allow: GET, HEAD, OPTIONS' "$work_dir/options.out"
    if grep -qi '^content-length:' "$work_dir/options.out"; then exit 1; fi
done
echo 'HTTP/3 regression passed: three fresh GET/HEAD/OPTIONS cycles'
