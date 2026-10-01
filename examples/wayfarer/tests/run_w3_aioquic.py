"""Reproducible Wayfarer W3 acceptance checks against a controlled aioquic peer.

Requires aioquic==1.3.0 and cryptography in the Python interpreter. Run:

    python3 examples/wayfarer/tests/run_w3_aioquic.py \
        --wayfarer /path/to/wayfarer --version both

Exit status is 0 when every check passes.
"""

import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import ipaddress
import json
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading

sys.dont_write_bytecode = True

import aioquic
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def certificate(directory):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = directory / "cert.pem", directory / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                         serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cert_path, key_path


@contextmanager
def fixture(directory, version):
    cert, key = certificate(directory)
    records, ready = [], queue.Queue()
    errors_path = directory / "server.stderr"
    with errors_path.open("w") as errors:
        command = [sys.executable, str(Path(__file__).with_name("w3_aioquic_server.py")),
                   "--version", version, "--cert", str(cert), "--key", str(key)]
        server = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=errors, text=True)

        def collect():
            for line in server.stdout:
                try:
                    record = json.loads(line)
                    records.append(record)
                    if record.get("event") == "ready":
                        ready.put(record)
                except ValueError:
                    records.append({"unparsed": line})
            ready.put(None)

        reader = threading.Thread(target=collect, daemon=True)
        reader.start()
        try:
            announcement = ready.get(timeout=10)
            if announcement is None:
                raise RuntimeError(f"fixture exited: {errors_path.read_text()}")
            yield announcement["port"], cert, records
        finally:
            server.terminate()
            try:
                server.wait(timeout=3)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=3)
            reader.join(timeout=3)
            server.stdout.close()
            if sys.exc_info()[0]:
                print(f"server records: {records}\n{errors_path.read_text()}", file=sys.stderr)


class Checks:
    def __init__(self):
        self.passed = 0
        self.failed = 0

    def ok(self, name):
        self.passed += 1
        print(f"ok   {name}")

    def fail(self, name, detail):
        self.failed += 1
        print(f"FAIL {name}: {detail}")

    def expect(self, name, condition, detail=""):
        if condition:
            self.ok(name)
        else:
            self.fail(name, detail)


def invoke(wayfarer, version, port, ca, target, extra=None, timeout_ms=5000):
    flag = "--http3" if version == "v1" else "--http3-v2"
    command = [str(wayfarer), flag, "--timeout-ms", str(timeout_ms)]
    if ca:
        command += ["--ca-file", str(ca)]
    if extra:
        command += extra
    command.append(f"https://127.0.0.1:{port}{target}")
    return subprocess.run(command, capture_output=True, timeout=timeout_ms / 1000 + 5)


def expect_basic(checks, wayfarer, version, port, cert, directory):
    result = invoke(wayfarer, version, port, cert, "/ok")
    checks.expect(f"{version} GET body",
                  result.returncode == 0 and result.stdout == b"ok-body"
                  and b"HTTP/3 200" in result.stderr,
                  f"rc={result.returncode}, stdout={result.stdout!r}, stderr={result.stderr!r}")

    result = invoke(wayfarer, version, port, cert, "/status/404")
    checks.expect(f"{version} 404 default",
                  result.returncode == 0 and result.stdout == b"status-body"
                  and b"HTTP/3 404" in result.stderr,
                  f"rc={result.returncode}, stderr={result.stderr!r}")

    result = invoke(wayfarer, version, port, cert, "/status/404", ["--fail"])
    checks.expect(f"{version} --fail 404", result.returncode == 22,
                  f"rc={result.returncode}, stderr={result.stderr!r}")

    result = invoke(wayfarer, version, port, cert, "/status/204")
    checks.expect(f"{version} 204 no body",
                  result.returncode == 0 and result.stdout == b""
                  and b"HTTP/3 204" in result.stderr,
                  f"rc={result.returncode}, stdout={result.stdout!r}")

    result = invoke(wayfarer, version, port, cert, "/ok", ["-X", "HEAD"])
    checks.expect(f"{version} HEAD no body",
                  result.returncode == 0 and result.stdout == b""
                  and b"HTTP/3 200" in result.stderr,
                  f"rc={result.returncode}, stdout={result.stdout!r}")

    result = invoke(wayfarer, version, port, cert, "/ok", ["-i"])
    checks.expect(f"{version} -i headers",
                  result.returncode == 0 and result.stdout.startswith(b"HTTP/3 200\r\n")
                  and b"content-type: text/plain" in result.stdout
                  and result.stdout.endswith(b"ok-body"),
                  f"rc={result.returncode}, stdout={result.stdout!r}")

    result = invoke(wayfarer, version, port, cert, "/split")
    checks.expect(f"{version} split DATA", result.returncode == 0 and result.stdout == b"abcdef",
                  f"rc={result.returncode}, stdout={result.stdout!r}")

    result = invoke(wayfarer, version, port, cert, "/binary")
    from w3_aioquic_server import BINARY_BODY
    checks.expect(f"{version} binary body",
                  result.returncode == 0 and result.stdout == BINARY_BODY,
                  f"rc={result.returncode}, bytes={len(result.stdout)}")

    result = invoke(wayfarer, version, port, cert, "/large")
    from w3_aioquic_server import LARGE_BODY
    checks.expect(f"{version} large body across DATA frames",
                  result.returncode == 0 and result.stdout == LARGE_BODY,
                  f"rc={result.returncode}, bytes={len(result.stdout)}")

    result = invoke(wayfarer, version, port, cert, "/manyfields-ok")
    checks.expect(f"{version} 128 fields accepted",
                  result.returncode == 0 and result.stdout == b"many-ok",
                  f"rc={result.returncode}, stderr={result.stderr!r}")

    result = invoke(wayfarer, version, port, cert, "/manyfields")
    checks.expect(f"{version} 129 fields rejected",
                  result.returncode == 1 and b"128 fields" in result.stderr,
                  f"rc={result.returncode}, stderr={result.stderr!r}")

    result = invoke(wayfarer, version, port, cert, "/huge", timeout_ms=20000)
    checks.expect(f"{version} body cap enforced",
                  result.returncode == 1 and b"16 MiB" in result.stderr,
                  f"rc={result.returncode}, stderr={result.stderr!r}")

    output = directory / f"binary-{version}.out"
    output.write_bytes(b"keep-me")
    result = invoke(wayfarer, version, port, cert, "/binary", ["-o", str(output)])
    checks.expect(f"{version} -o binary commit",
                  result.returncode == 0 and output.read_bytes() == BINARY_BODY,
                  f"rc={result.returncode}, size={output.stat().st_size if output.exists() else 'missing'}")

    # A failed -o transfer must preserve an existing destination.
    output.write_bytes(b"keep-me")
    result = invoke(wayfarer, version, port, cert, "/trailers", ["-o", str(output)])
    checks.expect(f"{version} -o failure preserves destination",
                  result.returncode == 1 and output.read_bytes() == b"keep-me",
                  f"rc={result.returncode}, body={output.read_bytes()!r}")

    result = invoke(wayfarer, version, port, cert, "/trailers")
    checks.expect(f"{version} trailers rejected",
                  result.returncode == 1 and b"trailers" in result.stderr,
                  f"rc={result.returncode}, stderr={result.stderr!r}")

    result = invoke(wayfarer, version, port, cert, "/badqp")
    checks.expect(f"{version} unsupported QPACK rejected",
                  result.returncode == 1 and b"unsupported" in result.stderr,
                  f"rc={result.returncode}, stderr={result.stderr!r}")

    for label, target in [("post-base", "/badqp-postbase"),
                          ("dynamic-name", "/badqp-dynamic-name")]:
        result = invoke(wayfarer, version, port, cert, target)
        checks.expect(f"{version} unsupported QPACK {label} rejected",
                      result.returncode == 1 and b"unsupported" in result.stderr,
                      f"rc={result.returncode}, stderr={result.stderr!r}")

    result = invoke(wayfarer, version, port, cert, "/oversized-headers")
    checks.expect(f"{version} oversized HEADERS rejected",
                  result.returncode == 1 and b"64 KiB" in result.stderr,
                  f"rc={result.returncode}, stderr={result.stderr!r}")

    result = invoke(wayfarer, version, port, cert, "/oversized-data")
    checks.expect(f"{version} oversized DATA rejected",
                  result.returncode == 1 and b"64 KiB" in result.stderr,
                  f"rc={result.returncode}, stderr={result.stderr!r}")

    result = invoke(wayfarer, version, port, cert, "/malformed")
    checks.expect(f"{version} malformed frame rejected",
                  result.returncode == 1 and b"incomplete" in result.stderr,
                  f"rc={result.returncode}, stderr={result.stderr!r}")

    result = invoke(wayfarer, version, port, cert, "/truncated")
    checks.expect(f"{version} truncated body rejected",
                  result.returncode == 1 and b"truncated" in result.stderr,
                  f"rc={result.returncode}, stderr={result.stderr!r}")

    result = invoke(wayfarer, version, port, cert, "/overlength")
    checks.expect(f"{version} overlength body rejected",
                  result.returncode == 1 and b"truncated" in result.stderr,
                  f"rc={result.returncode}, stderr={result.stderr!r}")

    result = invoke(wayfarer, version, port, cert, "/status/304-with-length")
    checks.expect(f"{version} 304 Content-Length tolerated",
                  result.returncode == 0 and result.stdout == b""
                  and b"HTTP/3 304" in result.stderr,
                  f"rc={result.returncode}, stderr={result.stderr!r}")

    result = invoke(wayfarer, version, port, cert, "/stall", timeout_ms=300)
    checks.expect(f"{version} deadline",
                  result.returncode == 1 and b"overall timeout" in result.stderr,
                  f"rc={result.returncode}, stderr={result.stderr!r}")


def expect_redirects(checks, wayfarer, version, port, cert, directory):
    for name, target in [("relative", "/redir/rel"), ("absolute", "/redir/abs"),
                         ("protocol-relative", "/redir/proto")]:
        result = invoke(wayfarer, version, port, cert, target, ["-L"])
        checks.expect(f"{version} redirect {name}",
                      result.returncode == 0 and result.stdout == b"ok-body",
                      f"rc={result.returncode}, stdout={result.stdout!r}, stderr={result.stderr!r}")

    result = invoke(wayfarer, version, port, cert, "/redir/rel", ["-L", "-i"])
    checks.expect(f"{version} redirect -i headers",
                  result.returncode == 0
                  and result.stdout.startswith(b"HTTP/3 302\r\n")
                  and b"location: /ok" in result.stdout
                  and b"HTTP/3 200\r\n" in result.stdout
                  and result.stdout.endswith(b"ok-body"),
                  f"rc={result.returncode}, stdout={result.stdout!r}")

    included = directory / f"redirect-include-{version}.out"
    result = invoke(wayfarer, version, port, cert, "/redir/rel", ["-L", "-i", "-o", str(included)])
    contents = included.read_bytes() if included.exists() else b""
    checks.expect(f"{version} redirect -i -o contents",
                  result.returncode == 0
                  and contents.startswith(b"HTTP/3 302\r\n")
                  and b"HTTP/3 200\r\n" in contents
                  and contents.endswith(b"ok-body"),
                  f"rc={result.returncode}, file={contents!r}")

    result = invoke(wayfarer, version, port, cert, "/redir/rel", ["-L", "-X", "HEAD"])
    checks.expect(f"{version} HEAD redirect",
                  result.returncode == 0 and result.stdout == b""
                  and result.stderr.count(b"HTTP/3 302") == 1
                  and result.stderr.count(b"HTTP/3 200") == 1,
                  f"rc={result.returncode}, stderr={result.stderr!r}")

    result = invoke(wayfarer, version, port, cert, "/redir/loop", ["-L"])
    checks.expect(f"{version} redirect loop rejected",
                  result.returncode == 1 and b"loop detected" in result.stderr,
                  f"rc={result.returncode}, stderr={result.stderr!r}")

    result = invoke(wayfarer, version, port, cert, "/redir/nolocation", ["-L"])
    checks.expect(f"{version} missing Location rejected",
                  result.returncode == 1 and b"no Location" in result.stderr,
                  f"rc={result.returncode}, stderr={result.stderr!r}")

    result = invoke(wayfarer, version, port, cert, "/redir/downgrade", ["-L"])
    checks.expect(f"{version} downgrade rejected",
                  result.returncode == 1 and b"non-HTTPS" in result.stderr,
                  f"rc={result.returncode}, stderr={result.stderr!r}")

    result = invoke(wayfarer, version, port, cert, "/hop/1", ["-L"])
    checks.expect(f"{version} ten redirects followed",
                  result.returncode == 0 and result.stdout == b"deep",
                  f"rc={result.returncode}, stdout={result.stdout!r}, stderr={result.stderr!r}")

    result = invoke(wayfarer, version, port, cert, "/hop/0", ["-L"])
    checks.expect(f"{version} redirect limit enforced",
                  result.returncode == 1 and b"limit of 10" in result.stderr,
                  f"rc={result.returncode}, stderr={result.stderr!r}")

    result = invoke(wayfarer, version, port, cert, "/redir/to404", ["-L", "--fail"])
    checks.expect(f"{version} --fail final redirected status",
                  result.returncode == 22,
                  f"rc={result.returncode}, stderr={result.stderr!r}")

    output = directory / f"redirect-{version}.out"
    output.write_bytes(b"keep-me")
    result = invoke(wayfarer, version, port, cert, "/redir/loop", ["-L", "-o", str(output)])
    checks.expect(f"{version} failed redirect -o preserves destination",
                  result.returncode == 1 and output.read_bytes() == b"keep-me",
                  f"rc={result.returncode}, body={output.read_bytes()!r}")


def expect_rejections(checks, wayfarer, version, port, cert):
    flag = "--http3" if version == "v1" else "--http3-v2"
    for name, extra in [("custom header", ["-H", "X-Test: 1"]),
                        ("request body", ["-d", "body"]),
                        ("POST method", ["-X", "POST"])]:
        result = subprocess.run(
            [str(wayfarer), flag, *extra, "--ca-file", str(cert),
             f"https://127.0.0.1:{port}/ok"], capture_output=True, timeout=10)
        checks.expect(f"{version} rejects {name}", result.returncode == 2,
                      f"rc={result.returncode}, stderr={result.stderr!r}")
    result = subprocess.run(
        [str(wayfarer), flag, "--ca-file", str(cert), "http://127.0.0.1:1/"],
        capture_output=True, timeout=10)
    checks.expect(f"{version} requires https", result.returncode == 2,
                  f"rc={result.returncode}, stderr={result.stderr!r}")


def run(wayfarer, version):
    checks = Checks()
    with tempfile.TemporaryDirectory(prefix=f"wayfarer-w3-{version}-") as temporary:
        directory = Path(temporary)
        with fixture(directory, version) as (port, cert, records):
            expect_basic(checks, wayfarer, version, port, cert, directory)
            expect_redirects(checks, wayfarer, version, port, cert, directory)
            expect_rejections(checks, wayfarer, version, port, cert)
        handshakes = [r for r in records if r.get("event") == "handshake"]
        requests = [r for r in records if r.get("event") == "request"]
        expected = 1 if version == "v1" else 0x6B3343CF
        checks.expect(f"{version} handshake version/ALPN",
                      bool(handshakes) and all(r["verified"] and r["version"] == expected
                                               for r in handshakes),
                      f"{handshakes}")
        checks.expect(f"{version} requests observed",
                      bool(requests) and all(r["verified"] and r["version"] == expected
                                             for r in requests),
                      f"{len(requests)} requests")
    return checks


if __name__ == "__main__":
    if aioquic.__version__ != "1.3.0":
        raise SystemExit("install aioquic==1.3.0 for these checks")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wayfarer", required=True, type=Path)
    parser.add_argument("--version", choices=["v1", "v2", "both"], default="both")
    arguments = parser.parse_args()
    selected = ["v1", "v2"] if arguments.version == "both" else [arguments.version]
    total_passed = total_failed = 0
    for version in selected:
        result = run(arguments.wayfarer.resolve(), version)
        total_passed += result.passed
        total_failed += result.failed
    print(f"PASS={total_passed} FAIL={total_failed}")
    sys.exit(1 if total_failed else 0)
