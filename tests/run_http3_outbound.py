"""Optional exact-version HTTP/3 outbound tests against pinned aioquic."""

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

from http3_aioquic_server import LARGE_BODY


def certificate(directory, wrong_identity=False):
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
                x509.IPAddress(ipaddress.ip_address(
                    "127.0.0.2" if wrong_identity else "127.0.0.1"))]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = directory / "cert.pem", directory / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                         serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cert_path, key_path


@contextmanager
def fixture(directory, version, wrong_identity=False, retry=False):
    cert, key = certificate(directory, wrong_identity)
    records, ready = [], queue.Queue()
    errors_path = directory / "server.stderr"
    with errors_path.open("w") as errors:
        command = [
            sys.executable, str(Path(__file__).with_name("http3_aioquic_server.py")),
            "--version", version, "--cert", str(cert), "--key", str(key)]
        if retry:
            command.append("--retry")
        server = subprocess.Popen(command,
            stdout=subprocess.PIPE, stderr=errors, text=True)

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
            announcement = ready.get(timeout=8)
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


def invoke(client, version, port, target, ca, timeout_ms=5000):
    command = [str(client), "--version", version, "--timeout-ms", str(timeout_ms)]
    if ca:
        command += ["--ca-file", str(ca)]
    command += [f"https://127.0.0.1:{port}{target}"]
    result = subprocess.run(command, capture_output=True, timeout=timeout_ms / 1000 + 5)
    if result.returncode < 0 or result.returncode > 2:
        raise RuntimeError(f"client crashed ({result.returncode}): {result.stderr!r}")
    return result


def multi_requests(client, version, port, cert, directory, count, sizes):
    output = directory / f"responses-{count}"
    command = [str(client), "--version", version, "--timeout-ms", "10000",
               "--ca-file", str(cert), "--output-dir", str(output)]
    paths = []
    for index in range(count):
        size = sizes[index % len(sizes)]
        path = f"/multi/{size}/{index}/{(count-index)*10}"
        paths.append(path)
        command += ["--request-path", path]
    command.append(f"https://127.0.0.1:{port}/")
    result = subprocess.run(command, capture_output=True, timeout=15)
    if result.returncode != 0 or result.stdout:
        raise RuntimeError(f"{version} {count} concurrent requests failed: "
                           f"rc={result.returncode}, stderr={result.stderr!r}")
    for index in range(count):
        size = sizes[index % len(sizes)]
        expected = bytes(((i * 17 + index) & 255) for i in range(size))
        if (output / f"{index}.body").read_bytes() != expected:
            raise RuntimeError(f"{version} request {index}: payload mismatch")
    if result.stderr.count(b"HTTP/3 200\n") != count:
        raise RuntimeError(f"{version}: missing response status")
    return paths


def run(client, version):
    expected_version = 1 if version == "v1" else 0x6B3343CF
    with tempfile.TemporaryDirectory(prefix=f"eventloop-http3-{version}-") as temporary:
        directory = Path(temporary)
        with fixture(directory, version) as (port, cert, records):
            authority = f"127.0.0.1:{port}"
            cases = [("", "/"), ("?x=1", "/?x=1"),
                     ("/echo/a%2Fb?x=1&x=2#ignored", "/echo/a%2Fb?x=1&x=2"),
                     ("/large", "/large"), ("/decoder-cancel", "/decoder-cancel"),
                     ("/empty", "/empty"),
                     ("/empty-content-length", "/empty-content-length"),
                     ("/missing", "/missing")]
            for target, path in cases:
                result = invoke(client, version, port, target, cert)
                status = 204 if path in ("/empty", "/empty-content-length") else \
                    404 if path == "/missing" else 200
                expected = (LARGE_BODY if path == "/large" else
                            b"" if path in ("/empty", "/empty-content-length")
                            else b"missing\n" if path == "/missing" else
                            json.dumps({"path": path, "authority": authority},
                                       sort_keys=True).encode() + b"\n")
                if (result.returncode != 0 or result.stdout != expected or
                        f"HTTP/3 {status}\n".encode() not in result.stderr):
                    raise RuntimeError(f"{version} {target!r}: rc={result.returncode}, "
                                       f"body={len(result.stdout)} bytes, stderr={result.stderr!r}")
            boundary_sizes = [0, 1, 2, 17, 63, 127, 255, 511, 512, 513,
                              1023, 4095, 4096, 4097, 65535, 65537, 131071, 262143]
            multi_cases = []
            for count, sizes in [(18, boundary_sizes),
                                  (26, [0, 17, 511, 512, 4095, 4096, 32769, 65537]),
                                  (32, [0, 17, 511, 512, 4095, 4096, 32769, 65537])]:
                multi_cases.append(multi_requests(client, version, port, cert,
                                                  directory, count, sizes))
            # A failing request must close sibling I/O and complete all tasks,
            # even when the first joined request is intentionally stalled.
            for paths, timeout_ms, message in [
                    (["/stall", "/empty-content-length-nonzero"], 2000,
                     b"HTTP/3 exchange failed"),
                    (["/stall", "/multi/4097/7/10"], 200,
                     b"HTTP/3 overall timeout")]:
                output = directory / ("failed-" + str(timeout_ms))
                command = [str(client), "--version", version,
                           "--timeout-ms", str(timeout_ms), "--ca-file", str(cert),
                           "--output-dir", str(output)]
                for path in paths:
                    command += ["--request-path", path]
                command += [f"https://127.0.0.1:{port}/"]
                failed = subprocess.run(command, capture_output=True, timeout=4)
                if failed.returncode != 1 or message not in failed.stderr:
                    raise RuntimeError(f"concurrent cleanup failed: {failed.stderr!r}")
            rejected = subprocess.run([str(client), "--output-dir", str(directory / "rejected"),
                *sum((["--request-path", "/"] for _ in range(33)), []),
                f"https://127.0.0.1:{port}/"], capture_output=True, timeout=2)
            if rejected.returncode != 2:
                raise RuntimeError("accepted more request paths than bounded capacity")
            for target in ("/empty-content-length-nonzero", "/empty-with-body"):
                invalid = invoke(client, version, port, target, cert)
                if (invalid.returncode != 1 or invalid.stdout or
                        b"HTTP/3 exchange failed" not in invalid.stderr):
                    raise RuntimeError(f"accepted invalid 204 {target}: "
                                       f"rc={invalid.returncode}, stderr={invalid.stderr!r}")
            invalid_ack = invoke(client, version, port, "/decoder-invalid-ack", cert)
            if (invalid_ack.returncode != 1 or
                    b"HTTP/3 exchange failed" not in invalid_ack.stderr):
                raise RuntimeError("accepted invalid QPACK section acknowledgement: "
                                   f"rc={invalid_ack.returncode}, stderr={invalid_ack.stderr!r}")
            untrusted = invoke(client, version, port, "/", None, timeout_ms=1000)
            if untrusted.returncode != 1 or b"HTTP/3 200" in untrusted.stderr:
                raise RuntimeError(f"untrusted certificate accepted: {untrusted.stderr!r}")
            stalled = invoke(client, version, port, "/stall", cert, timeout_ms=200)
            if stalled.returncode != 1 or b"HTTP/3 overall timeout" not in stalled.stderr:
                raise RuntimeError(f"exchange deadline failed: {stalled.stderr!r}")
        handshakes = [r for r in records if r.get("event") == "handshake"]
        requests = [r for r in records if r.get("event") == "request"]
        if any(r.get("event") == "retry" for r in records):
            raise RuntimeError(f"unexpected Retry in ordinary fixture: {records}")
        if (not handshakes or any(not r["verified"] or r["version"] != expected_version
                                  for r in handshakes) or
                any(not r["valid"] or r["version"] != expected_version for r in requests)):
            raise RuntimeError(f"exact version or request verification failed: {records}")
        for paths in multi_cases:
            selected = [r for r in requests if r["path"] in paths]
            if (len(selected) != len(paths) or len({r["connection"] for r in selected}) != 1 or
                    len({r["stream"] for r in selected}) != len(paths)):
                raise RuntimeError(f"requests did not share one connection: {selected}")
            connection = selected[0]["connection"]
            completed = [r for r in records if r.get("event") == "response-complete"
                         and r["connection"] == connection]
            if len(completed) != len(paths):
                raise RuntimeError(f"incomplete server responses: {completed}")
            if [r["stream"] for r in completed] == sorted(r["stream"] for r in completed):
                raise RuntimeError("fixture did not exercise out-of-order completion")
        for _, path in cases:
            if not any(r["path"] == path and r["authority"] == authority for r in requests):
                raise RuntimeError(f"server did not verify request path {path!r}")
        with fixture(directory, version, wrong_identity=True) as (port, cert, _):
            wrong = invoke(client, version, port, "/", cert, timeout_ms=1000)
            if wrong.returncode != 1 or b"HTTP/3 200" in wrong.stderr:
                raise RuntimeError(f"wrong certificate identity accepted: {wrong.stderr!r}")
        with fixture(directory, version, retry=True) as (port, cert, retry_records):
            authority = f"127.0.0.1:{port}"
            for path in ("/retry", "/large"):
                result = invoke(client, version, port, path, cert)
                expected = (LARGE_BODY if path == "/large" else
                            json.dumps({"path": path, "authority": authority},
                                       sort_keys=True).encode() + b"\n")
                if (result.returncode != 0 or result.stdout != expected or
                        b"HTTP/3 200\n" not in result.stderr):
                    raise RuntimeError(f"{version} Retry {path}: rc={result.returncode}, "
                                       f"body={len(result.stdout)} bytes, stderr={result.stderr!r}")
        retries = [r for r in retry_records if r.get("event") == "retry"]
        retry_handshakes = [r for r in retry_records if r.get("event") == "handshake"]
        retry_requests = [r for r in retry_records if r.get("event") == "request"]
        if (len(retries) != 2 or len(retry_handshakes) != 2 or len(retry_requests) != 2 or
                any(r["version"] != expected_version or not r["token_bytes"] for r in retries) or
                any(not r["verified"] or r["version"] != expected_version
                    for r in retry_handshakes) or
                {r["source_cid"] for r in retries} !=
                {r["retry_source_cid"] for r in retry_handshakes} or
                any(not r["valid"] or r["version"] != expected_version or
                    r["authority"] != authority for r in retry_requests) or
                {r["path"] for r in retry_requests} != {"/retry", "/large"}):
            raise RuntimeError(f"Retry send/restart verification failed: {retry_records}")
        # Bound-but-silent UDP peer verifies the deadline includes handshake.
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as silent:
            silent.bind(("127.0.0.1", 0))
            stalled = invoke(client, version, silent.getsockname()[1], "/", cert,
                             timeout_ms=200)
            if stalled.returncode != 1 or b"HTTP/3 overall timeout" not in stalled.stderr:
                raise RuntimeError(f"handshake deadline failed: {stalled.stderr!r}")
    print(f"PASS {version}: exact independent version, URL/authority, 32 KiB binary body, "
          "18/26/32 concurrent request streams, boundary/binary/interleaved/out-of-order bodies, "
          "status, certificate trust/identity, handshake/exchange deadlines, "
          "Retry send and accepted token restart")


if __name__ == "__main__":
    if aioquic.__version__ != "1.3.0":
        raise RuntimeError("install aioquic==1.3.0 for this optional matrix")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", required=True, type=Path)
    parser.add_argument("--version", choices=["v1", "v2", "both"], default="both")
    arguments = parser.parse_args()
    for selected in ["v1", "v2"] if arguments.version == "both" else [arguments.version]:
        run(arguments.client.resolve(), selected)
