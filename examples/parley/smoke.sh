#!/usr/bin/env bash
# Exercises Parley over HTTP/2 with curl: accounts, conversations, realtime
# events, receipts, uploads, ranged media, access control, graceful
# shutdown, and journal replay.
set -euo pipefail

server=${1:?usage: smoke.sh /path/to/parley [port]}
port=${2:-18443}
work=$(mktemp -d)
server_pid=
events_pid=
cleanup() {
    local status=$?
    trap - EXIT
    set +e
    [[ -n "$events_pid" ]] && kill "$events_pid" 2>/dev/null
    if [[ -n "$server_pid" ]]; then
        kill -INT "$server_pid" 2>/dev/null
        wait "$server_pid" 2>/dev/null
    fi
    if (( status != 0 )) && [[ -f "$work/server.log" ]]; then
        echo "Parley log:" >&2
        cat "$work/server.log" >&2
    fi
    rm -rf "$work"
    exit "$status"
}
trap cleanup EXIT

base="https://localhost:$port"
start() {
    "$server" --data "$work/data" --port "$port" >> "$work/server.log" 2>&1 &
    server_pid=$!
    for _ in $(seq 50); do
        curl -sk -o /dev/null "$base/" && return
        sleep 0.1
    done
    echo "server did not start" >&2
    return 1
}
stop() {
    kill -INT "$server_pid"
    wait "$server_pid"
    server_pid=
}
api() { # jar method path [curl args...]
    local jar=$1 method=$2 path=$3
    shift 3
    curl -sk --http2 -b "$work/$jar" -c "$work/$jar" -H "origin: $base" -X "$method" "$base$path" "$@"
}
expect() { # description haystack needle
    if [[ "$2" != *"$3"* ]]; then
        echo "FAIL: $1: expected '$3' in: $2" >&2
        exit 1
    fi
    echo "ok: $1"
}

start
expect "register alice" "$(api alice POST /api/register -d '{"username":"alice","name":"Alice","password":"password1"}')" '"username":"alice"'
expect "register bob" "$(api bob POST /api/register -d '{"username":"bob","name":"Bob","password":"password2"}')" '"username":"bob"'
expect "register carol" "$(api carol POST /api/register -d '{"username":"carol","name":"Carol","password":"password3"}')" '"username":"carol"'
expect "duplicate username" "$(api x POST /api/register -d '{"username":"alice","name":"A","password":"password1"}')" 'taken'
expect "wrong password" "$(api x POST /api/login -d '{"username":"bob","password":"nope-nope"}' -w '%{http_code}')" '401'
expect "unauthenticated" "$(api x GET /api/bootstrap -w '%{http_code}')" '401'
expect "cross-origin" "$(curl -sk -b "$work/alice" -H 'origin: https://evil.example' -X POST "$base/api/command" -d '{}' -w '%{http_code}')" '403'
expect "direct chat" "$(api alice POST /api/conversations -d '{"user":2}')" '"id":1'

api bob GET /api/events -N > "$work/events" &
events_pid=$!
sleep 0.5
expect "send text" "$(api alice POST /api/command -d '{"t":"send","conv":1,"text":"hello bob","client_id":"c1"}')" '{}'
expect "upload" "$(api alice POST '/api/upload?name=notes%20v1.txt' -H 'content-type: text/plain' --data-binary 'abcdefghijklmnopqrstuvwxyz')" '"kind":"file"'
media=$(ls "$work/data/media")
expect "send document" "$(api alice POST /api/command -d "{\"t\":\"send\",\"conv\":1,\"media\":\"$media\"}")" '{}'
expect "read receipt" "$(api bob POST /api/command -d '{"t":"read","conv":1,"upto":2}')" '{}'
expect "ranged download" "$(api bob GET "/media/$media" -H 'range: bytes=2-5')" 'cdef'
expect "attachment header" "$(api bob GET "/media/$media" -D - -o /dev/null)" "filename*=UTF-8''notes%20v1.txt"
expect "outsider denied" "$(api carol GET "/media/$media" -o /dev/null -w '%{http_code}')" '404'
expect "outsider history" "$(api carol GET '/api/messages?conv=1' -w '%{http_code}')" '404'
sleep 0.3
events=$(cat "$work/events")
expect "event: message" "$events" '"text":"hello bob"'
expect "event: document" "$events" '"name":"notes v1.txt"'
expect "event: receipt" "$events" '"t":"receipt","conv":1,"user":2,"delivered":2,"read":2'
kill "$events_pid"
events_pid=

stop # wait fails the script unless SIGINT shutdown exits 0
echo "ok: graceful exit"
start
expect "history replayed" "$(api alice GET '/api/messages?conv=1')" '"text":"hello bob"'
expect "receipts replayed" "$(api alice GET /api/bootstrap)" '{"user":2,"delivered":2,"read":2}'
echo "Parley smoke test passed"
