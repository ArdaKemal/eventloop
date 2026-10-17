#!/usr/bin/env bash
# Launches headless Chrome with bot pages against a running Skirmish server.
# Usage: ./swarm.sh [bots=16] [pages=1] [port=4443]
set -euo pipefail

BOTS="${1:-16}"
PAGES="${2:-1}"
PORT="${3:-4443}"

case "$(uname -s)" in
  Darwin) CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" ;;
  *) CHROME="$(command -v google-chrome || true)" ;;
esac
if [[ -z "$CHROME" || ! -x "$CHROME" ]]; then
  echo "swarm.sh: Chrome not found" >&2
  exit 1
fi

PROFILE="$(mktemp -d "${TMPDIR:-/tmp}/skirmish-swarm.XXXXXX")"
CHILD=""

cleanup() {
  trap - EXIT INT TERM
  if [[ -n "$CHILD" ]]; then
    kill "$CHILD" 2>/dev/null || true
    wait "$CHILD" 2>/dev/null || true
  fi
  rm -rf "$PROFILE"
}
trap cleanup EXIT INT TERM

URLS=()
for ((i = 0; i < PAGES; i++)); do
  URLS+=("https://localhost:${PORT}/bots.html?n=${BOTS}")
done

echo "swarm: ${PAGES} page(s) x ${BOTS} bots against https://localhost:${PORT}" >&2

# Chrome writes console messages to stderr; keep only those lines.
"$CHROME" \
  --headless=new \
  --ignore-certificate-errors \
  --no-first-run \
  --enable-logging=stderr \
  --v=0 \
  --user-data-dir="$PROFILE" \
  "${URLS[@]}" \
  2> >(grep --line-buffered 'CONSOLE' >&2) &
CHILD=$!
wait "$CHILD" || true
