#!/usr/bin/env bash
set -euo pipefail

test_binary=$1
test_directory=$(mktemp -d)
trap 'rm -rf "$test_directory"' EXIT

openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$test_directory/key.pem" \
    -out "$test_directory/certificate.pem" \
    -days 1 -subj /CN=localhost \
    -addext subjectAltName=DNS:localhost \
    >/dev/null 2>&1

"$test_binary" "$test_directory/certificate.pem" "$test_directory/key.pem"
