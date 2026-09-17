#!/usr/bin/env bash
# Compare the bundled HTTP server with nginx and lighttpd on loopback.
# All servers use one worker, the same generated static file, HTTP keep-alive,
# and the same wrk invocation.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
build_dir=${BUILD_DIR:-"$root/build/benchmark"}
duration=${DURATION:-15s}
connections=${CONNECTIONS:-128}
threads=${THREADS:-1}
file_size=${FILE_SIZE:-4096}
cpu=${CPU:-0}
server=${SERVER:-all}

for command in wrk nginx lighttpd curl taskset; do
    command -v "$command" >/dev/null || {
        echo "missing required command: $command" >&2
        exit 1
    }
done

cmake -S "$root" -B "$build_dir" -DCMAKE_BUILD_TYPE=Release
cmake --build "$build_dir" --target http_benchmark_server --parallel

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/eventloop-http-benchmark.XXXXXX")
server_pid=''
cleanup() {
    if [[ -n "$server_pid" ]] && kill -0 "$server_pid" 2>/dev/null; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    rm -rf "$work_dir"
}
trap cleanup EXIT INT TERM

mkdir "$work_dir/www"
head -c "$file_size" /dev/zero | tr '\0' 'x' > "$work_dir/www/payload.bin"

cat > "$work_dir/nginx.conf" <<EOF
worker_processes 1;
pid $work_dir/nginx.pid;
error_log $work_dir/nginx-error.log warn;
events { worker_connections 4096; }
http {
    access_log off;
    default_type application/octet-stream;
    sendfile on;
    keepalive_timeout 60;
    server {
        listen 127.0.0.1:18081;
        root $work_dir/www;
        location = /payload.bin { try_files /payload.bin =404; }
    }
}
EOF

cat > "$work_dir/lighttpd.conf" <<EOF
server.document-root = "$work_dir/www"
server.bind = "127.0.0.1"
server.port = 18082
server.max-worker = 1
server.max-connections = 4096
server.pid-file = "$work_dir/lighttpd.pid"
server.errorlog = "$work_dir/lighttpd-error.log"
server.modules = ()
index-file.names = ( "index.html" )
mimetype.assign = ( "" => "application/octet-stream" )
EOF

wait_until_ready() {
    local port=$1
    for _ in {1..100}; do
        if curl --silent --fail --output /dev/null "http://127.0.0.1:$port/payload.bin"; then
            return 0
        fi
        sleep 0.05
    done
    echo "server on port $port did not become ready" >&2
    return 1
}

run_one() {
    local name=$1 port=$2
    shift 2
    echo
    echo "=== $name (file=${file_size} B, connections=${connections}, duration=${duration}) ==="
    taskset -c "$cpu" "$@" > "$work_dir/$name.log" 2>&1 &
    server_pid=$!
    if ! wait_until_ready "$port"; then
        sed -n '1,120p' "$work_dir/$name.log" >&2 || true
        return 1
    fi
    # Warm the page cache and connection path without recording it.
    wrk -t"$threads" -c"$connections" -d2s "http://127.0.0.1:$port/payload.bin" >/dev/null
    taskset -c "$cpu" wrk -t"$threads" -c"$connections" -d"$duration" --latency \
        "http://127.0.0.1:$port/payload.bin"
    kill "$server_pid"
    wait "$server_pid" 2>/dev/null || true
    server_pid=''
}

echo "Building/using: $build_dir/http_benchmark_server"
echo "Pinned load generator and server to CPU $cpu; run on an otherwise idle machine."
case "$server" in
    all)
        run_one eventloop 18080 "$build_dir/http_benchmark_server" "$work_dir/www" 18080
        run_one nginx 18081 nginx -c "$work_dir/nginx.conf" -g 'daemon off;'
        run_one lighttpd 18082 lighttpd -D -f "$work_dir/lighttpd.conf"
        ;;
    eventloop) run_one eventloop 18080 "$build_dir/http_benchmark_server" "$work_dir/www" 18080 ;;
    nginx) run_one nginx 18081 nginx -c "$work_dir/nginx.conf" -g 'daemon off;' ;;
    lighttpd) run_one lighttpd 18082 lighttpd -D -f "$work_dir/lighttpd.conf" ;;
    *) echo "SERVER must be all, eventloop, nginx, or lighttpd" >&2; exit 2 ;;
esac
