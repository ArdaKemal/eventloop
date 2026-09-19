#!/usr/bin/env bash
# Measure the bundled HTTP server's throughput as listener threads scale.
# The server is pinned to SERVER_CPUS and the load generator to CLIENT_CPUS so
# they do not contend for the same cores. Each listener thread runs its own
# event loop and binds with SO_REUSEPORT.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
build_dir=${BUILD_DIR:-"$root/build/benchmark"}
duration=${DURATION:-10s}
connections=${CONNECTIONS:-256}
wrk_threads=${WRK_THREADS:-4}
file_size=${FILE_SIZE:-4096}
server_cpus=${SERVER_CPUS:-0-7}
client_cpus=${CLIENT_CPUS:-8-15}
server_threads=${SERVER_THREADS:-"1 2 4 8"}
port=${PORT:-18080}

for command in wrk curl taskset; do
    command -v "$command" >/dev/null || {
        echo "missing required command: $command" >&2
        exit 1
    }
done

cmake -S "$root" -B "$build_dir" -DCMAKE_BUILD_TYPE=Release
cmake --build "$build_dir" --target http_benchmark_server --parallel

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/eventloop-http-scaling.XXXXXX")
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

echo "eventloop HTTP scaling: file=${file_size} B, connections=${connections}, duration=${duration}"
echo "server cpus=${server_cpus}, client cpus=${client_cpus}, wrk threads=${wrk_threads}"
echo

printf '%8s %16s %14s %16s\n' "threads" "requests" "Requests/sec" "Transfer/sec"
for threads in $server_threads; do
    taskset -c "$server_cpus" "$build_dir/http_benchmark_server" \
        "$work_dir/www" "$port" "$threads" > "$work_dir/server-$threads.log" 2>&1 &
    server_pid=$!
    if ! wait_until_ready "$port"; then
        sed -n '1,80p' "$work_dir/server-$threads.log" >&2 || true
        exit 1
    fi

    taskset -c "$client_cpus" wrk -t"$wrk_threads" -c"$connections" -d2s \
        "http://127.0.0.1:$port/payload.bin" >/dev/null
    taskset -c "$client_cpus" wrk -t"$wrk_threads" -c"$connections" \
        -d"$duration" --latency "http://127.0.0.1:$port/payload.bin" \
        > "$work_dir/wrk-$threads.log" 2>&1

    kill "$server_pid"
    wait "$server_pid" 2>/dev/null || true
    server_pid=''

    requests=$(awk '/requests in/{print $1}' "$work_dir/wrk-$threads.log")
    rate=$(awk '/Requests\/sec:/{print $2}' "$work_dir/wrk-$threads.log")
    transfer=$(awk '/Transfer\/sec:/{print $2}' "$work_dir/wrk-$threads.log")
    printf '%8s %16s %14s %16s\n' "$threads" "$requests" "$rate" "$transfer"

    echo "  --- wrk detail (threads=$threads) ---"
    sed -n '/Latency Distribution/,$p' "$work_dir/wrk-$threads.log" | sed 's/^/  /'
done
