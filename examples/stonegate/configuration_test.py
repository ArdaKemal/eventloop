#!/usr/bin/env python3
"""Exercise Stonegate through its executable, including listener ownership."""
import contextlib
import http.client
import pathlib
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time

SERVER = str(pathlib.Path(sys.argv[1]).resolve())


def request(port, path="/", tls=False):
    connection = (http.client.HTTPSConnection("127.0.0.1", port, timeout=2,
                  context=ssl._create_unverified_context()) if tls else
                  http.client.HTTPConnection("127.0.0.1", port, timeout=2))
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def ports(count):
    with contextlib.ExitStack() as stack:
        sockets = [stack.enter_context(socket.socket()) for _ in range(count)]
        for sock in sockets:
            sock.bind(("127.0.0.1", 0))
        return [sock.getsockname()[1] for sock in sockets]


@contextlib.contextmanager
def running(config, *arguments):
    with tempfile.TemporaryFile(mode="w+") as log:
        process = subprocess.Popen([SERVER, "--config", str(config), *arguments],
                                   stdout=log, stderr=log)
        try:
            yield process
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
            try:
                code = process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise AssertionError("Stonegate did not retire its listeners")
            log.seek(0)
            output = log.read()
            assert code == 0, (code, output)


def listening(port, kind):
    """Counts this host's listening TCP or bound UDP IPv4 sockets on port."""
    table = pathlib.Path(f"/proc/net/{kind}").read_text().splitlines()[1:]
    state = "0A" if kind == "tcp" else "07"
    return sum(1 for line in table
               if int(line.split()[1].split(":")[1], 16) == port and line.split()[3] == state)


def ready(process, port, tls=False):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        assert process.poll() is None, "Stonegate exited during startup"
        try:
            if request(port, tls=tls)[0] == 200:
                return
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(0.025)
    raise AssertionError("listener did not become ready")


def main(work):
    (work / "public").mkdir()
    (work / "public" / "index.html").write_text("website\n")
    (work / "public" / "files").mkdir()
    (work / "public" / "files" / "item.txt").write_text("item\n")
    (work / "downloads").mkdir()
    (work / "downloads" / "index.html").write_text("downloads\n")
    (work / "downloads" / "files").mkdir()
    (work / "downloads" / "files" / "download.txt").write_text("download\n")
    (work / "sites").mkdir()
    main_config = work / "stonegate.toml"
    base = '[defaults]\nroot = "public"\n'

    def check(contents, expected=None, *arguments):
        main_config.write_text(contents)
        result = subprocess.run([SERVER, "--config", str(main_config), "--check", *arguments],
                                capture_output=True, text=True, timeout=5)
        output = result.stdout + result.stderr
        assert "PRIVATE_SENTINEL_739" not in output, output
        if expected is None:
            assert result.returncode == 0 and "Configuration OK" in output, output
        else:
            assert result.returncode == 1 and expected in output, (expected, result.returncode, output)
        return output

    check(base)
    cases = [
        ('root="public"', "unknown top-level"),
        (base + 'root = "public"\n', "duplicate key"),
        (base + 'unknown = "PRIVATE_SENTINEL_739"\n', "unknown setting"),
        (base + 'directory_listing = "true"\n', "wrong TOML type"),
        (base + 'header_timeout_ms = -1\n', "invalid value"),
        (base + 'idle_timeout_ms = 3600001\n', "invalid value"),
        (base + 'open_file_cache_capacity = 65537\n', "invalid value"),
        (base + 'bind = "PRIVATE_SENTINEL_739"\n', "invalid IP address"),
        (base + '[defaults.http]\nport = 65536\n', "invalid value"),
        (base + '[defaults.http]\nport = "8080"\n', "wrong TOML type"),
        (base + '[defaults.http]\nmode = "PRIVATE_SENTINEL_739"\n', "must be serve"),
        (base + '[defaults.tls]\nkey_password = "PRIVATE_SENTINEL_739"\n', "requires TLS"),
        (base + '[defaults.tls]\ncertificate = "cert.pem"\n', "supplied together"),
        (base + '[defaults.tls]\nkey_password = "broken', "line 4, column"),
        (base + '[defaults.http3]\nport = 8444\n', "requires certificate"),
        (base + '[defaults.http3]\nconnections = 257\n', "invalid value"),
        (base + '[defaults.http3]\nrequests = 8193\n', "invalid value"),
        (base + '[defaults.http3]\nmax_datagram = 1199\n', "invalid value"),
        (base + 'root_extra = "\\u0000"\n', "unknown setting"),
        ('[defaults]\nroot = "public\\u0000"\n', "contains NUL"),
        (base + '[[server]]\nname = "bad name"\n', "invalid server name"),
        (base + '[[server]]\nname="one"\n[[server]]\nname="one"\n', "duplicate server name"),
        (base + '[[server]]\nname="one"\n[[server]]\nname="two"\n', "overlapping"),
        (base + '[runtime]\nshutdown_seconds = false\n', "wrong TOML type"),
        (base + '[runtime]\nshutdown_seconds = 3601\n', "invalid value"),
        (base + '[runtime]\nworkers = 0\n', "invalid value"),
        (base + '[runtime]\nworkers = 257\n', "invalid value"),
        (base + '[runtime]\nworkers = "4"\n', "wrong TOML type"),
        ('include=["missing.toml"]\n' + base, "cannot open config"),
        ('include=["stonegate.toml"]\n' + base, "cyclic include"),
        (base + '[[server]]\nroot="missing"\n', "existing directory"),
        (base + '[defaults.http]\nmode="redirect"\n', "required for redirect"),
        (base + '[defaults.http]\nmode="off"\n', "requires a TLS or HTTP/3 listener"),
    ]
    for contents, error in cases:
        check(contents, error)
    check(base, "duplicate --config", "--config", str(main_config))
    check(base, "unknown --server", "--server", "missing")
    check(base, "invalid value", "--workers", "0")
    if sys.platform.startswith("linux"):
        check(base + '[runtime]\nworkers = 256\n')
    else:
        check(base + '[runtime]\nworkers = 2\n', "require Linux")
    check(base + '[defaults.http3]\nrequests=0\nport=0\n')
    check(base + '[defaults.tls]\nport=0\n')
    check(base + 'tls=false\n', "defaults.tls: wrong TOML type")
    check(base + '[defaults.tls]\nhttp2=0\n', "defaults.tls.http2: wrong TOML type")
    check(base + '[defaults.http]\nredirect_host="bad\\u0001host"\n', "redirect-host must be")
    check(base + 'directory_listing=true # comment\nheader_timeout_ms=0\nidle_timeout_ms=0\n')
    check('#' * 65537, "exceeds 64 KiB")
    check('include=[' + ','.join('"unused"' for _ in range(2050)) + ']', "node capacity")
    check(base + ''.join('[[server]]\n' for _ in range(17)), "server capacity")
    for index in range(9):
        (work / f"depth{index}.toml").write_text(f'include=["depth{index+1}.toml"]\n')
    check('include=["depth0.toml"]\n' + base, "depth exceeds 8")
    (work / "sites" / "bad.toml").write_text('[defaults]\nroot="../public"\n')
    check('include=["sites/bad.toml"]\n' + base, "forbidden in include")
    (work / "sites" / "empty.toml").write_text('# empty fragment\n')
    check('include=["sites/empty.toml","sites/../sites/empty.toml"]\n' + base, "cyclic include")
    for index in range(32):
        (work / f"file{index}.toml").write_text('# empty\n')
    check('include=[' + ','.join(f'"file{i}.toml"' for i in range(32)) + ']\n' + base,
          "file capacity")
    for index in range(17):
        (work / f"file{index}.toml").write_text('#' * 65536)
    check('include=[' + ','.join(f'"file{i}.toml"' for i in range(17)) + ']\n' + base,
          "combined config")
    print("TOML types, diagnostics, secret redaction and explicit limits: PASS")

    first, second = ports(2)
    (work / "sites" / "downloads.toml").write_text(f'''[[server]]
name = "downloads"
root = "../downloads"
directory_listing = true
[server.http]
port = {second}
''')
    config = f'''include = ["sites/downloads.toml"]
[defaults]
root = "public"
bind = "127.0.0.1"
directory_listing = false
open_file_cache_capacity = 4
header_timeout_ms = 100
idle_timeout_ms = 100
[defaults.http]
port = {first}
[[server]]
name = "website"
'''
    assert "2 server(s)" in check(config)
    check(config.replace('bind = "127.0.0.1"', 'bind = "0.0.0.0"').replace(
        'name = "website"', 'name = "website"\nbind = "127.0.0.1"').replace(
        f'port = {first}', f'port = {second}'), "overlapping")
    # Different numeric spellings of the same IPv6 endpoint still collide.
    check(base + 'bind="::1"\n[[server]]\nbind="0:0:0:0:0:0:0:1"\n[[server]]\n', "overlapping")
    check(config, "require --server", "--root", str(work / "downloads"))
    check(config, None, "--server", "website", "--root", str(work / "public"))
    with running(main_config) as process:
        ready(process, first)
        ready(process, second)
        assert request(first) == (200, b"website\n")
        assert request(second) == (200, b"downloads\n")
        assert request(first, "/healthz") == (200, b"ok\n")
        assert request(first, "/files/")[0] != 200
        assert b"download.txt" in request(second, "/files/")[1]
        # Inherited header timeout is wired to the listener.
        with socket.create_connection(("127.0.0.1", first), timeout=2) as slow:
            slow.settimeout(2)
            slow.sendall(b"GET / HTTP/1.1\r\n")
            assert slow.recv(1) == b"", "header timeout was not applied"
        # Config checking works while the configured ports are occupied.
        check(config)
    with running(main_config, "--server", "website", "--root", str(work / "downloads")) as process:
        ready(process, first)
        ready(process, second)
        assert request(first) == request(second) == (200, b"downloads\n")
    print("Includes, inheritance, scoped CLI overrides, timeouts, SIGINT/rebind: PASS")

    # Validate a copy of the shipped example with its relative document root.
    shutil.copyfile(pathlib.Path(__file__).with_name("stonegate.toml.example"), main_config)
    result = subprocess.run([SERVER, "--config", str(main_config), "--check"],
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stderr
    result = subprocess.run([SERVER, "--root", str(work / "downloads"), "--http2", "off",
                            "--config", str(main_config), "--check", "--shutdown-seconds", "0"],
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stderr

    openssl = shutil.which("openssl")
    assert openssl, "OpenSSL CLI is required for TLS checks"
    subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=localhost", "-keyout", str(work / "key.pem"),
                    "-out", str(work / "cert.pem")], check=True, capture_output=True)
    one, two = ports(2)
    tls_config = base + f'''[defaults.http]
mode="off"
[defaults.tls]
certificate="cert.pem"
private_key="key.pem"
http2=false
[[server]]
name="first"
[server.tls]
port={one}
[server.http3]
port={one}
[[server]]
name="second"
root="downloads"
[server.tls]
port={two}
[server.http3]
port={two}
'''
    check(tls_config)
    check(tls_config, "does not accept key-password", "--server", "first", "--key-password", "PRIVATE_SENTINEL_739")
    check(tls_config, "cannot load private key", "--server", "first", "--http3-port", "0",
          "--private-key", str(work / "cert.pem"))
    check(tls_config)
    curl = shutil.which("curl")
    curl_h3 = curl and "HTTP3" in subprocess.run(
        [curl, "--version"], capture_output=True, text=True, check=True).stdout
    with running(main_config) as process:
        ready(process, one, tls=True)
        ready(process, two, tls=True)
        assert request(one, tls=True) == (200, b"website\n")
        assert request(two, tls=True) == (200, b"downloads\n")
        if curl_h3:
            for port, body in [(one, b"website\n"), (two, b"downloads\n")]:
                for _ in range(2):
                    result = subprocess.run([curl, "--http3-only", "--silent", "--show-error",
                        "--fail", "--max-time", "4", "--cacert", str(work / "cert.pem"),
                        "--resolve", f"localhost:{port}:127.0.0.1", f"https://localhost:{port}/"],
                        capture_output=True, timeout=5)
                    assert result.returncode == 0 and result.stdout == body, result.stderr
            print("Repeated HTTP/3 requests across both configured endpoints: PASS")
        else:
            print("Multi-server HTTP/3 requests: SKIP (curl lacks HTTP3)")
    with running(main_config) as process:
        ready(process, one, tls=True)
        ready(process, two, tls=True)
    print("Two TLS/HTTP3 listeners, credential validation and endpoint retirement: PASS")

    if sys.platform.startswith("linux"):
        with running(main_config, "--workers", "3") as process:
            ready(process, one, tls=True)
            ready(process, two, tls=True)
            # Every worker owns its own TCP and UDP sockets on each port.
            for port in (one, two):
                assert listening(port, "tcp") == 3, ("tcp", port)
                assert listening(port, "udp") == 3, ("udp", port)
            for _ in range(12):
                assert request(one, tls=True) == (200, b"website\n")
                assert request(two, tls=True) == (200, b"downloads\n")
            if curl_h3:
                for port, body in [(one, b"website\n"), (two, b"downloads\n")]:
                    for _ in range(6):
                        result = subprocess.run([curl, "--http3-only", "--silent",
                            "--show-error", "--fail", "--max-time", "4", "--cacert",
                            str(work / "cert.pem"), "--resolve", f"localhost:{port}:127.0.0.1",
                            f"https://localhost:{port}/"], capture_output=True, timeout=5)
                        assert result.returncode == 0 and result.stdout == body, result.stderr
        print("Three workers share TLS and HTTP/3 listeners and stop on SIGINT: PASS")

    # A later bind failure must retire the earlier TCP/HTTP3 tasks, not abort.
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", two))
        occupied.listen()
        result = subprocess.run([SERVER, "--config", str(main_config)],
                                capture_output=True, text=True, timeout=5)
        assert result.returncode == 1, (result.returncode, result.stderr)
    with running(main_config) as process:
        ready(process, one, tls=True)
        ready(process, two, tls=True)
    if sys.platform.startswith("linux"):
        # A failing worker stops the workers that already started.
        with socket.socket() as occupied:
            occupied.bind(("127.0.0.1", two))
            occupied.listen()
            result = subprocess.run([SERVER, "--config", str(main_config), "--workers", "3"],
                                    capture_output=True, text=True, timeout=5)
            assert result.returncode == 1, (result.returncode, result.stderr)
    print("Partial startup failure retires earlier listener tasks: PASS")


with tempfile.TemporaryDirectory(prefix="stonegate-config-") as directory:
    main(pathlib.Path(directory))
