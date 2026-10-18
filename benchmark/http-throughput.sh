#!/usr/bin/env bash
# Compare the bundled HTTP server with nginx and lighttpd at one or more
# worker counts. The server is pinned to SERVER_CPUS and the load generator to
# CLIENT_CPUS so they do not contend for the same cores. Examples:
#   benchmark/http-throughput.sh                                # one worker each
#   WORKERS="1 8" benchmark/http-throughput.sh                  # multicore
#   SERVER=eventloop WORKERS="1 2 4 8" benchmark/http-throughput.sh  # thread scaling
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
build_dir=${BUILD_DIR:-"$root/build/benchmark"}
duration=${DURATION:-5s}
connections=${CONNECTIONS:-256}
wrk_threads=${WRK_THREADS:-4}
file_size=${FILE_SIZE:-4096}
server_cpus=${SERVER_CPUS:-0-7}
client_cpus=${CLIENT_CPUS:-8-15}
workers=${WORKERS:-1}
server=${SERVER:-all}

for command in wrk curl taskset; do
    command -v "$command" >/dev/null || {
        echo "missing required command: $command" >&2
        exit 1
    }
done

cmake -S "$root" -B "$build_dir" -DCMAKE_BUILD_TYPE=Release
cmake --build "$build_dir" --target http_benchmark_server --parallel

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/eventloop-http-throughput.XXXXXX")
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

wait_until_ready() {
    local port=$1
    for _ in {1..200}; do
        if curl --silent --fail --output /dev/null "http://127.0.0.1:$port/payload.bin"; then
            return 0
        fi
        sleep 0.05
    done
    echo "server on port $port did not become ready" >&2
    return 1
}

bench() {
    local label=$1 port=$2
    shift 2
    taskset -c "$server_cpus" "$@" > "$work_dir/$label.log" 2>&1 &
    server_pid=$!
    if ! wait_until_ready "$port"; then
        sed -n '1,80p' "$work_dir/$label.log" >&2 || true
        exit 1
    fi
    taskset -c "$client_cpus" wrk -t"$wrk_threads" -c"$connections" -d2s \
        "http://127.0.0.1:$port/payload.bin" >/dev/null
    taskset -c "$client_cpus" wrk -t"$wrk_threads" -c"$connections" \
        -d"$duration" --latency "http://127.0.0.1:$port/payload.bin" \
        > "$work_dir/$label.wrk" 2>&1
    kill "$server_pid"
    wait "$server_pid" 2>/dev/null || true
    server_pid=''
    local rate transfer
    rate=$(awk '/Requests\/sec:/{print $2}' "$work_dir/$label.wrk")
    transfer=$(awk '/Transfer\/sec:/{print $2}' "$work_dir/$label.wrk")
    printf '%-12s %-8s %14s %16s\n' "${label%%-*}" "${label##*-}" "$rate" "$transfer"
}

echo "HTTP throughput comparison: file=${file_size} B, connections=${connections}, duration=${duration}"
echo "server cpus=${server_cpus}, client cpus=${client_cpus}, wrk threads=${wrk_threads}"
echo
printf '%-12s %-8s %14s %16s\n' "server" "workers" "Requests/sec" "Transfer/sec"

for count in $workers; do
    if [[ "$server" == "all" || "$server" == "eventloop" ]]; then
        bench "eventloop-$count" 18080 \
            "$build_dir/http_benchmark_server" "$work_dir/www" 18080 "$count"
    fi
    if [[ "$server" == "all" || "$server" == "nginx" ]]; then
        cat > "$work_dir/nginx-$count.conf" <<EOF
worker_processes $count;
pid $work_dir/nginx-$count.pid;
error_log $work_dir/nginx-$count-error.log warn;
events { worker_connections 4096; }
http {
    access_log off;
    default_type application/octet-stream;
    sendfile on;
    keepalive_timeout 60;
    server {
        listen 127.0.0.1:18081 reuseport;
        root $work_dir/www;
        location = /payload.bin { try_files /payload.bin =404; }
    }
}
EOF
        bench "nginx-$count" 18081 nginx -c "$work_dir/nginx-$count.conf" -g 'daemon off;'
    fi
    if [[ "$server" == "all" || "$server" == "lighttpd" ]]; then
        cat > "$work_dir/lighttpd-$count.conf" <<EOF
server.document-root = "$work_dir/www"
server.bind = "127.0.0.1"
server.port = 18082
server.max-worker = $count
server.max-connections = 4096
server.pid-file = "$work_dir/lighttpd-$count.pid"
server.errorlog = "$work_dir/lighttpd-$count-error.log"
server.modules = ()
index-file.names = ( "index.html" )
mimetype.assign = ( "" => "application/octet-stream" )
EOF
        bench "lighttpd-$count" 18082 lighttpd -D -f "$work_dir/lighttpd-$count.conf"
    fi
done
