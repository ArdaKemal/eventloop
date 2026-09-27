#!/usr/bin/env bash
set -euo pipefail

test_binary=$1
test_directory=$(mktemp -d)
trap 'rm -rf "$test_directory"' EXIT

openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$test_directory/ca-key.pem" \
    -out "$test_directory/ca.pem" \
    -days 1 -subj /CN=eventloop-test-CA \
    -addext basicConstraints=critical,CA:TRUE \
    -addext keyUsage=critical,keyCertSign,cRLSign \
    >/dev/null 2>&1

openssl req -newkey rsa:2048 -nodes \
    -keyout "$test_directory/key.pem" \
    -out "$test_directory/request.csr" \
    -subj /CN=localhost \
    >/dev/null 2>&1

cat >"$test_directory/extensions.cnf" <<'EOF'
subjectAltName=DNS:localhost
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF

openssl x509 -req -in "$test_directory/request.csr" \
    -CA "$test_directory/ca.pem" -CAkey "$test_directory/ca-key.pem" \
    -CAcreateserial -out "$test_directory/certificate.pem" \
    -days 1 -extfile "$test_directory/extensions.cnf" \
    >/dev/null 2>&1

mkdir "$test_directory/trust"
cp "$test_directory/ca.pem" "$test_directory/trust/ca.pem"
touch "$test_directory/index.txt"
echo 1000 >"$test_directory/crlnumber"
cat >"$test_directory/ca.cnf" <<EOF
[ ca ]
default_ca=local_ca
[ local_ca ]
database=$test_directory/index.txt
new_certs_dir=$test_directory
certificate=$test_directory/ca.pem
private_key=$test_directory/ca-key.pem
default_md=sha256
default_crl_days=1
crlnumber=$test_directory/crlnumber
EOF
openssl ca -config "$test_directory/ca.cnf" -gencrl \
    -out "$test_directory/trust/ca.crl" >/dev/null 2>&1

"$test_binary" "$test_directory/certificate.pem" "$test_directory/key.pem" \
    "$test_directory/trust"
