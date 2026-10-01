#!/usr/bin/env bash
set -euo pipefail

server=${1:?usage: smoke.sh /path/to/stonegate}
work=$(mktemp -d)
server_pid=
cleanup() {
    local status=$?
    trap - EXIT
    set +e
    if [[ -n "$server_pid" ]]; then
        kill -INT "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    if (( status != 0 )); then
        for log in "$work"/server.log "$work"/server2.log "$work"/server3.log; do
            if [[ -f "$log" ]]; then
                echo "Stonegate log: $log" >&2
                cat "$log" >&2
            fi
        done
    fi
    rm -rf "$work"
    exit "$status"
}
trap cleanup EXIT

mkdir "$work/root"
printf 'stonegate-ok\n' > "$work/root/index.html"
mkdir "$work/root/files"
printf 'listed\n' > "$work/root/files/asset.txt"
printf 'outside\n' > "$work/outside.txt"
ln -s "$work/outside.txt" "$work/root/leak.txt"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
    -keyout "$work/key.pem" -out "$work/cert.pem" >/dev/null 2>&1

http_port=$((20000 + RANDOM % 20000))
https_port=$((40000 + RANDOM % 20000))
http3_port=$https_port
"$server" --root "$work/root" --bind 127.0.0.1 \
    --http-mode redirect --redirect-host localhost \
    --http-port "$http_port" --https-port "$https_port" --http3-port "$http3_port" \
    --certificate "$work/cert.pem" --private-key "$work/key.pem" \
    >"$work/server.log" 2>&1 &
server_pid=$!

ready=0
for _ in {1..100}; do
    if curl --silent --max-time 1 "http://127.0.0.1:$http_port/" >/dev/null; then
        ready=1
        break
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
        cat "$work/server.log" >&2
        exit 1
    fi
    sleep 0.1
done
if (( !ready )); then
    cat "$work/server.log" >&2
    exit 1
fi

redirect=$(curl --silent --http1.1 --output /dev/null --write-out '%{http_code} %{redirect_url}' \
    "http://127.0.0.1:$http_port/")
[[ "$redirect" == "308 https://localhost:$https_port/" ]] || {
    echo "unexpected redirect: $redirect" >&2
    exit 1
}

body=$(curl --silent --fail --http1.1 --cacert "$work/cert.pem" \
    --resolve "localhost:$https_port:127.0.0.1" "https://localhost:$https_port/")
[[ "$body" == stonegate-ok ]] || { echo 'HTTP/1.1 body mismatch' >&2; exit 1; }
echo 'HTTP/1.1 redirect and TLS response: PASS'

if curl --version | grep -q HTTP2; then
    version=$(curl --silent --fail --http2 --cacert "$work/cert.pem" \
        --resolve "localhost:$https_port:127.0.0.1" \
        --output "$work/h2-body" --write-out '%{http_version}' \
        "https://localhost:$https_port/")
    [[ "$version" == 2 && $(cat "$work/h2-body") == stonegate-ok ]] || {
        echo "HTTP/2 expected, got version $version" >&2
        exit 1
    }
    echo 'TLS HTTP/2 response: PASS'
else
    echo 'TLS HTTP/2 response: SKIP (curl lacks HTTP2)'
fi

header_value() {
    awk -v wanted="$2" '
        { sub(/\r$/, ""); colon = index($0, ":")
          if (colon && tolower(substr($0, 1, colon - 1)) == wanted) {
              value = substr($0, colon + 1)
              sub(/^[ \t]*/, "", value)
              print value
              exit
          } }
    ' "$1"
}

if curl --version | grep -Eq '(^|[[:space:]])HTTP3([[:space:]]|$)'; then
    h3_url="https://localhost:$http3_port/"
    h3_resolve="localhost:$http3_port:127.0.0.1"
    for round in 1 2 3; do
        get_result=$(curl --silent --show-error --fail --http3-only --max-time 8 \
            --cacert "$work/cert.pem" --resolve "$h3_resolve" \
            --dump-header "$work/h3-get-$round.headers" \
            --output "$work/h3-get-$round.body" \
            --write-out '%{http_code} %{http_version}' "$h3_url")
        [[ "$get_result" == '200 3' ]] || {
            echo "HTTP/3 GET expected 200 and version 3, got $get_result" >&2; exit 1;
        }
        cmp -s "$work/root/index.html" "$work/h3-get-$round.body" || {
            echo "HTTP/3 GET body mismatch in round $round" >&2; exit 1;
        }

        head_result=$(curl --silent --show-error --fail --http3-only --head --max-time 8 \
            --cacert "$work/cert.pem" --resolve "$h3_resolve" \
            --dump-header "$work/h3-head-$round.headers" --output /dev/null \
            --write-out '%{http_code} %{http_version} %{size_download}' "$h3_url")
        [[ "$head_result" == '200 3 0' ]] || {
            echo "HTTP/3 HEAD expected 200, version 3, and no body; got $head_result" >&2; exit 1;
        }
        expected_length=$(wc -c < "$work/root/index.html" | tr -d '[:space:]')
        actual_length=$(header_value "$work/h3-head-$round.headers" content-length)
        [[ "$actual_length" == "$expected_length" ]] || {
            echo "HTTP/3 HEAD Content-Length mismatch in round $round: $actual_length" >&2; exit 1;
        }

        options_result=$(curl --silent --show-error --fail --http3-only -X OPTIONS --max-time 8 \
            --cacert "$work/cert.pem" --resolve "$h3_resolve" \
            --dump-header "$work/h3-options-$round.headers" \
            --output "$work/h3-options-$round.body" \
            --write-out '%{http_code} %{http_version}' "$h3_url")
        [[ "$options_result" == '204 3' && ! -s "$work/h3-options-$round.body" ]] || {
            echo "HTTP/3 OPTIONS expected 204, version 3, and no body; got $options_result" >&2; exit 1;
        }
        allow=$(header_value "$work/h3-options-$round.headers" allow)
        [[ "$allow" == 'GET, HEAD, OPTIONS' ]] || {
            echo "HTTP/3 OPTIONS Allow mismatch in round $round: $allow" >&2; exit 1;
        }
        if grep -Eiq '^content-length:' "$work/h3-options-$round.headers"; then
            echo "HTTP/3 OPTIONS unexpectedly sent Content-Length in round $round" >&2; exit 1;
        fi

        after_result=$(curl --silent --show-error --fail --http3-only --max-time 8 \
            --cacert "$work/cert.pem" --resolve "$h3_resolve" \
            --output "$work/h3-after-$round.body" \
            --write-out '%{http_code} %{http_version}' "$h3_url")
        [[ "$after_result" == '200 3' ]] &&
            cmp -s "$work/root/index.html" "$work/h3-after-$round.body" || {
            echo "HTTP/3 GET after OPTIONS failed in round $round: $after_result" >&2; exit 1;
        }
    done
    echo 'HTTP/3 repeated GET, HEAD, OPTIONS, GET on fresh connections: PASS'
else
    echo 'HTTP/3 repeated GET, HEAD, OPTIONS, GET: SKIP (curl lacks HTTP3)'
fi

if ! kill -INT "$server_pid"; then
    cat "$work/server.log" >&2
    echo 'first Stonegate process could not receive SIGINT' >&2
    exit 1
fi
if wait "$server_pid"; then
    :
else
    status=$?
    cat "$work/server.log" >&2
    echo "first Stonegate process exited after SIGINT with status $status" >&2
    exit 1
fi
server_pid=

"$server" --root "$work/root" --bind 127.0.0.1 --http-mode off \
    --https-port "$https_port" --http2 off \
    --certificate "$work/cert.pem" --private-key "$work/key.pem" \
    >"$work/server2.log" 2>&1 &
server_pid=$!
ready=0
for _ in {1..100}; do
    if curl --silent --fail --http1.1 --cacert "$work/cert.pem" \
        --resolve "localhost:$https_port:127.0.0.1" \
        "https://localhost:$https_port/" >/dev/null; then
        ready=1
        break
    fi
    sleep 0.1
done
(( ready )) || { cat "$work/server2.log" >&2; exit 1; }
echo 'TLS listener rebind after SIGINT: PASS'
version=$(curl --silent --fail --http1.1 --cacert "$work/cert.pem" \
    --resolve "localhost:$https_port:127.0.0.1" \
    --output /dev/null --write-out '%{http_version}' \
    "https://localhost:$https_port/")
[[ "$version" == 1.1 ]] || { echo "HTTP/1.1 expected, got $version" >&2; exit 1; }
echo 'TLS HTTP/1.1 only: PASS'

if ! kill -INT "$server_pid"; then
    cat "$work/server2.log" >&2
    echo 'second Stonegate process could not receive SIGINT' >&2
    exit 1
fi
if wait "$server_pid"; then
    :
else
    status=$?
    cat "$work/server2.log" >&2
    echo "second Stonegate process exited after SIGINT with status $status" >&2
    exit 1
fi
server_pid=

"$server" --root "$work/root" --bind 127.0.0.1 \
    --directory-listing --reuse-port \
    --http-port "$http_port" >"$work/server3.log" 2>&1 &
server_pid=$!
ready=0
for _ in {1..100}; do
    if curl --silent --fail --http1.1 "http://127.0.0.1:$http_port/" >/dev/null; then
        ready=1
        break
    fi
    sleep 0.1
done
(( ready )) || { cat "$work/server3.log" >&2; exit 1; }
body=$(curl --silent --fail --http1.1 "http://127.0.0.1:$http_port/")
[[ "$body" == stonegate-ok ]] || { echo 'plain HTTP/1.1 body mismatch' >&2; exit 1; }
head_code=$(curl --silent --output /dev/null --write-out '%{http_code}' \
    --head "http://127.0.0.1:$http_port/")
[[ "$head_code" == 200 ]] || { echo "HEAD returned $head_code" >&2; exit 1; }
listing=$(curl --silent --fail "http://127.0.0.1:$http_port/files/")
[[ "$listing" == *asset.txt* ]] || { echo 'directory listing missing asset' >&2; exit 1; }
for target in '/..%2foutside.txt' '/%2e%2e/outside.txt'; do
    code=$(curl --silent --path-as-is --output "$work/traversal.body" \
        --write-out '%{http_code}' "http://127.0.0.1:$http_port$target")
    [[ "$code" == 400 ]] && ! grep -q outside "$work/traversal.body" || {
        echo "path traversal unexpectedly served $target (status $code)" >&2; exit 1;
    }
done
code=$(curl --silent --output "$work/symlink.body" --write-out '%{http_code}' \
    "http://127.0.0.1:$http_port/leak.txt")
[[ "$code" == 404 ]] && ! grep -q outside "$work/symlink.body" || {
    echo "symlink outside document root unexpectedly served (status $code)" >&2; exit 1;
}
echo 'Plain HTTP/1.1 response: PASS'
echo 'HEAD and directory listing: PASS'
echo 'Path traversal and outside-root symlink rejection: PASS'
