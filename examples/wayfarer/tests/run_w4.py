"""Reproducible Wayfarer W4 checks across HTTP/1.1, HTTP/2, and HTTP/3.

Exercises `-I`/`--head`, `-O`/`--remote-name`, filename derivation and
sanitization, existing-file replacement/failure preservation, stderr metadata,
and clean stdout. Requires aioquic 1.3.0 (HTTP/3) and h2 (HTTP/2).

    python3 examples/wayfarer/tests/run_w4.py \
        --wayfarer /path/to/wayfarer --version all
"""

import argparse
from contextlib import contextmanager
import json
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading
import time

sys.dont_write_bytecode = True
from run_w3_aioquic import certificate

TESTS = Path(__file__).resolve().parent
STATUS = {"h1": b"HTTP/1.1", "h2": b"HTTP/2", "h3": b"HTTP/3"}

FILENAME_CASES = [
    ("/file.txt", "file.txt"),
    ("/dir/data.bin?x=1&y=2", "data.bin"),
    ("/a%20b.txt", "a b.txt"),
    ("/sub/", "index.html"),
    ("/", "index.html"),
    ("/.", "index.html"),
    ("/..", "index.html"),
    ("/foo/..", "index.html"),
    ("/%2e%2e", "index.html"),
    ("/.hidden", ".hidden"),
    ("/..%2F..%2Fetc%2Fpasswd", "passwd"),
    ("/a%2Fb", "b"),
    ("/...", "..."),
]


def expected_body(mode, target):
    if mode == "h3":
        return f"path={target}".encode()
    return b"w4 " + target.encode("latin-1", "replace")


@contextmanager
def fixture(mode, directory, cert, key):
    if mode == "h1":
        command = [sys.executable, str(TESTS / "w4_http_server.py"), "--mode", "h1"]
    elif mode == "h2":
        command = [sys.executable, str(TESTS / "w4_http_server.py"), "--mode", "h2",
                   "--cert", str(cert), "--key", str(key)]
    else:
        command = [sys.executable, str(TESTS / "w3_aioquic_server.py"), "--version", "v1",
                   "--cert", str(cert), "--key", str(key)]
    records, ready = [], queue.Queue()
    errors_path = directory / f"{mode}.stderr"
    with errors_path.open("w") as errors:
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
                raise RuntimeError(f"{mode} fixture exited: {errors_path.read_text()}")
            yield announcement["port"], records
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
                print(f"{mode} records: {records}\n{errors_path.read_text()}", file=sys.stderr)


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


def invoke(wayfarer, mode, port, ca, target, extra=None, timeout_ms=5000, cwd=None):
    flag = {"h1": "--http1.1", "h2": "--http2", "h3": "--http3"}[mode]
    scheme = "http" if mode == "h1" else "https"
    command = [str(wayfarer), flag, "--timeout-ms", str(timeout_ms)]
    if ca:
        command += ["--ca-file", str(ca)]
    if extra:
        command += extra
    command.append(f"{scheme}://127.0.0.1:{port}{target}")
    return subprocess.run(command, capture_output=True, timeout=timeout_ms / 1000 + 5, cwd=cwd)


def listing(directory):
    return sorted(path.name for path in directory.iterdir())


def check_remote_names(checks, wayfarer, mode, port, ca, directory):
    for index, (target, expected) in enumerate(FILENAME_CASES):
        cwd = directory / f"remote-{mode}-{index}"
        cwd.mkdir()
        result = invoke(wayfarer, mode, port, ca, target, ["-O"], cwd=cwd)
        body = (cwd / expected).read_bytes() if (cwd / expected).exists() else b""
        checks.expect(f"{mode} -O {target!r} -> {expected}",
                      result.returncode == 0 and listing(cwd) == [expected]
                      and result.stdout == b"" and b"saving to" in result.stderr
                      and body == expected_body(mode, target),
                      f"rc={result.returncode}, files={listing(cwd)}, "
                      f"stdout={result.stdout!r}, stderr={result.stderr!r}")


def check_unsafe_name(checks, wayfarer, mode, port, ca, directory):
    cwd = directory / f"unsafe-{mode}"
    cwd.mkdir()
    result = invoke(wayfarer, mode, port, ca, "/a%5Cb", ["-O"], cwd=cwd)
    checks.expect(f"{mode} -O rejects a backslash name",
                  result.returncode == 2 and listing(cwd) == []
                  and b"safe output name" in result.stderr,
                  f"rc={result.returncode}, files={listing(cwd)}, stderr={result.stderr!r}")


def check_collision(checks, wayfarer, mode, port, ca, directory):
    cwd = directory / f"collision-{mode}"
    cwd.mkdir()
    (cwd / "file.txt").write_bytes(b"old-content")
    result = invoke(wayfarer, mode, port, ca, "/file.txt", ["-O"], cwd=cwd)
    checks.expect(f"{mode} -O replaces existing file",
                  result.returncode == 0
                  and (cwd / "file.txt").read_bytes() == expected_body(mode, "/file.txt")
                  and listing(cwd) == ["file.txt"],
                  f"rc={result.returncode}, files={listing(cwd)}")


def check_preserve(checks, wayfarer, mode, port, ca, directory):
    cwd = directory / f"preserve-{mode}"
    cwd.mkdir()
    (cwd / "stall").write_bytes(b"keep-me")
    result = invoke(wayfarer, mode, port, ca, "/stall", ["-O"], timeout_ms=300, cwd=cwd)
    checks.expect(f"{mode} -O failure preserves destination",
                  result.returncode == 1
                  and (cwd / "stall").read_bytes() == b"keep-me"
                  and listing(cwd) == ["stall"],
                  f"rc={result.returncode}, files={listing(cwd)}")


def check_head(checks, wayfarer, mode, port, ca, directory):
    prefix = STATUS[mode]
    result = invoke(wayfarer, mode, port, ca, "/file.txt", ["-I"])
    checks.expect(f"{mode} -I headers only",
                  result.returncode == 0 and result.stdout.startswith(prefix + b" 200")
                  and expected_body(mode, "/file.txt") not in result.stdout
                  and prefix + b" 200" in result.stderr,
                  f"rc={result.returncode}, stdout={result.stdout!r}, stderr={result.stderr!r}")

    result = invoke(wayfarer, mode, port, ca, "/file.txt", ["--head"])
    checks.expect(f"{mode} --head alias",
                  result.returncode == 0 and result.stdout.startswith(prefix + b" 200")
                  and expected_body(mode, "/file.txt") not in result.stdout,
                  f"rc={result.returncode}, stdout={result.stdout!r}")

    cwd = directory / f"head-remote-{mode}"
    cwd.mkdir()
    result = invoke(wayfarer, mode, port, ca, "/file.txt", ["-I", "-O"], cwd=cwd)
    content = (cwd / "file.txt").read_bytes() if (cwd / "file.txt").exists() else b""
    checks.expect(f"{mode} -I -O headers to file",
                  result.returncode == 0 and result.stdout == b""
                  and content.startswith(prefix + b" 200")
                  and expected_body(mode, "/file.txt") not in content,
                  f"rc={result.returncode}, content={content!r}")

    cwd = directory / f"include-remote-{mode}"
    cwd.mkdir()
    result = invoke(wayfarer, mode, port, ca, "/file.txt", ["-O", "-i"], cwd=cwd)
    content = (cwd / "file.txt").read_bytes() if (cwd / "file.txt").exists() else b""
    checks.expect(f"{mode} -O -i headers and body",
                  result.returncode == 0 and content.startswith(prefix + b" 200")
                  and content.endswith(expected_body(mode, "/file.txt")),
                  f"rc={result.returncode}, content={content!r}")


def check_rejections(checks, wayfarer, mode, port, ca):
    for name, extra in [("-I with -X GET", ["-I", "-X", "GET"]),
                        ("-I with a body", ["-I", "-d", "x"]),
                        ("-O with -o", ["-O", "-o", "x"])]:
        result = invoke(wayfarer, mode, port, ca, "/file.txt", extra, timeout_ms=2000)
        checks.expect(f"{mode} rejects {name}", result.returncode == 2,
                      f"rc={result.returncode}, stderr={result.stderr!r}")


def check_http3_extras(checks, wayfarer, mode, port, ca, directory):
    if mode != "h3":
        return
    cwd = directory / "redirect-remote"
    cwd.mkdir()
    result = invoke(wayfarer, mode, port, ca, "/redir/rel", ["-O", "-L"], cwd=cwd)
    body = (cwd / "rel").read_bytes() if (cwd / "rel").exists() else b""
    checks.expect("h3 -O -L derives the name from the original URL",
                  result.returncode == 0 and listing(cwd) == ["rel"]
                  and body == b"ok-body" and result.stdout == b"",
                  f"rc={result.returncode}, files={listing(cwd)}, body={body!r}")

    result = invoke(wayfarer, mode, port, ca, "/status/404", ["-I", "--fail"])
    checks.expect("h3 -I --fail reports the final 404",
                  result.returncode == 22,
                  f"rc={result.returncode}, stderr={result.stderr!r}")


def requests_for(records, prefix, count):
    """Waits briefly for the fixture's output reader to record count requests."""
    deadline = time.monotonic() + 2
    while True:
        matches = [record for record in list(records) if record.get("event") == "request"
                   and record.get("target", "").startswith(prefix)]
        if len(matches) >= count or time.monotonic() > deadline:
            return matches
        time.sleep(0.01)


def check_http2_reuse(checks, wayfarer, mode, port, ca, records):
    """RFC 9113 9.1.1: a redirect to another host covered by the certificate,
    at the same address, reuses the connection; 421 forces a new one."""
    if mode != "h2":
        return
    result = invoke(wayfarer, mode, port, ca, "/coalesce/reuse.txt", ["-L"])
    seen = requests_for(records, "/coalesce/reuse.txt", 1) + requests_for(records, "/reuse.txt", 1)
    checks.expect("h2 -L reuses the connection for a covered host",
                  result.returncode == 0 and result.stdout == expected_body(mode, "/reuse.txt")
                  and len(seen) == 2 and seen[0]["connection"] == seen[1]["connection"],
                  f"rc={result.returncode}, stdout={result.stdout!r}, seen={seen}")

    result = invoke(wayfarer, mode, port, ca, "/coalesce/misdirected/x", ["-L"])
    first = requests_for(records, "/coalesce/misdirected/x", 1)
    retried = requests_for(records, "/misdirected/x", 2)
    checks.expect("h2 421 retries on a new connection",
                  result.returncode == 0
                  and result.stdout == expected_body(mode, "/misdirected/x")
                  and len(first) == 1 and len(retried) == 2
                  and retried[0]["connection"] == first[0]["connection"]
                  and retried[1]["connection"] != first[0]["connection"],
                  f"rc={result.returncode}, stdout={result.stdout!r}, "
                  f"first={first}, retried={retried}")


def run(wayfarer, modes):
    checks = Checks()
    help_result = subprocess.run([str(wayfarer), "--help"], capture_output=True, timeout=10)
    checks.expect("help lists --head and --remote-name",
                  help_result.returncode == 0 and b"--head" in help_result.stdout
                  and b"--remote-name" in help_result.stdout,
                  f"stdout={help_result.stdout!r}")
    with tempfile.TemporaryDirectory(prefix="wayfarer-w4-") as temporary:
        directory = Path(temporary)
        cert, key = certificate(directory)
        for mode in modes:
            with fixture(mode, directory, cert, key) as (port, records):
                ca = cert if mode != "h1" else None
                check_remote_names(checks, wayfarer, mode, port, ca, directory)
                check_unsafe_name(checks, wayfarer, mode, port, ca, directory)
                check_collision(checks, wayfarer, mode, port, ca, directory)
                check_preserve(checks, wayfarer, mode, port, ca, directory)
                check_head(checks, wayfarer, mode, port, ca, directory)
                check_rejections(checks, wayfarer, mode, port, ca)
                check_http3_extras(checks, wayfarer, mode, port, ca, directory)
                check_http2_reuse(checks, wayfarer, mode, port, ca, records)
                methods = {record.get("method") for record in records
                           if record.get("event") == "request"}
                checks.expect(f"{mode} server saw HEAD and GET requests",
                              "HEAD" in methods and "GET" in methods,
                              f"methods={methods}")
    return checks


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wayfarer", required=True, type=Path)
    parser.add_argument("--version", choices=["h1", "h2", "h3", "all"], default="all")
    arguments = parser.parse_args()
    selected = ["h1", "h2", "h3"] if arguments.version == "all" else [arguments.version]
    result = run(arguments.wayfarer.resolve(), selected)
    print(f"PASS={result.passed} FAIL={result.failed}")
    sys.exit(1 if result.failed else 0)
