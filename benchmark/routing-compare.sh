#!/usr/bin/env bash
# Compares routed and static responses of the same size on HTTP/1.1 (wrk),
# HTTP/2 (h2load), and HTTP/3 (h2load with QUIC, when available). One server
# loop, pinned to one CPU; the load generator runs on other CPUs. The routed
# handler answers from memory while static requests read a file, so this
# compares the two serving paths, not routing overhead alone. Results vary
# between runs; compare medians from the same machine and session.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
build_dir=${BUILD_DIR:-"$root/build/benchmark"}
duration=${DURATION:-10}
connections=${CONNECTIONS:-64}
streams=${STREAMS:-10}
file_size=${FILE_SIZE:-4096}
server_cpu=${SERVER_CPU:-0}
client_cpus=${CLIENT_CPUS:-2-5}
base_port=${BASE_PORT:-18090}
repeats=${REPEATS:-3}

for command in wrk h2load openssl taskset curl; do
    command -v "$command" >/dev/null || { echo "missing required command: $command" >&2; exit 1; }
done

cmake -S "$root" -B "$build_dir" -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build "$build_dir" --target routing_benchmark_server --parallel >/dev/null

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/eventloop-routing-benchmark.XXXXXX")
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
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$work_dir/key.pem" -out "$work_dir/cert.pem" -days 2 \
    -subj /CN=localhost -addext subjectAltName=DNS:localhost 2>/dev/null

taskset -c "$server_cpu" "$build_dir/routing_benchmark_server" \
    "$work_dir/www" "$work_dir/cert.pem" "$work_dir/key.pem" "$base_port" \
    > "$work_dir/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 50); do
    grep -q ready "$work_dir/server.log" 2>/dev/null && break
    sleep 0.1
done

h1="http://127.0.0.1:$base_port"
h2="https://127.0.0.1:$((base_port + 1))"
h3="https://127.0.0.1:$((base_port + 2))"
for path in /routed /payload.bin; do
    size=$(curl -s -o /dev/null -w '%{size_download}' "$h1$path")
    [[ "$size" == "$file_size" ]] || { echo "unexpected size $size for $path" >&2; exit 1; }
done

h3_supported=0
if taskset -c "$client_cpus" h2load -n 1 -c 1 --alpn-list=h3 "$h3/routed" 2>/dev/null |
        grep -q "1 succeeded"; then
    h3_supported=1
fi

median() { sort -n | awk '{ value[NR] = $1 } END { print value[int((NR + 1) / 2)] }'; }

run_wrk() {
    taskset -c "$client_cpus" wrk -t4 -c"$connections" -d"${duration}s" "$1" |
        awk '/Requests\/sec/ { print int($2) }'
}

run_h2load() {
    local alpn=$1 url=$2
    taskset -c "$client_cpus" h2load -t4 -c"$connections" -m"$streams" -D"$duration" \
        --alpn-list="$alpn" "$url" 2>/dev/null |
        awk '/^finished in/ { gsub(",", "", $4); print int($4) }'
}

echo "payload ${file_size} B, ${connections} connections, ${streams} streams (HTTP/2, HTTP/3),"
echo "${duration}s per run, median of ${repeats}; server on CPU ${server_cpu}, client on ${client_cpus}"
printf '%-9s %14s %14s %8s\n' protocol "routed req/s" "static req/s" "routed/static"
report() {
    local name=$1 runner=$2 alpn=$3 base=$4
    local routed static
    routed=$(for _ in $(seq "$repeats"); do $runner $alpn "$base/routed"; done | median)
    static=$(for _ in $(seq "$repeats"); do $runner $alpn "$base/payload.bin"; done | median)
    printf '%-9s %14s %14s %8.2f\n' "$name" "$routed" "$static" \
        "$(awk -v r="$routed" -v s="$static" 'BEGIN { print r / s }')"
}
wrk_runner() { run_wrk "$1"; }
report HTTP/1.1 wrk_runner "" "$h1"
report HTTP/2 run_h2load h2 "$h2"
if (( h3_supported )); then report HTTP/3 run_h2load h3 "$h3"; else echo "HTTP/3    skipped (h2load lacks QUIC)"; fi
