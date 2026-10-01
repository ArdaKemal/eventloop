#!/usr/bin/env python3
"""Probe public HTTPS sites with curl's HTTP/2 client (not eventloop's client)."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import os
import shutil
import subprocess
import sys
from urllib.parse import urlsplit


DEFAULT_URLS = (
    "https://www.google.com/",
    "https://www.cloudflare.com/",
    "https://www.wikipedia.org/",
    "https://github.com/",
    "https://www.python.org/",
    "https://www.mozilla.org/",
    "https://www.apple.com/",
    "https://www.microsoft.com/",
    "https://www.rust-lang.org/",
    "https://www.kernel.org/",
)


def probe(url: str, connect_timeout: int, timeout: int) -> tuple[str, str, str, str]:
    command = [
        "curl", "--http2", "--location", "--proto-redir", "=https",
        "--silent", "--show-error", "--output", os.devnull,
        "--connect-timeout", str(connect_timeout), "--max-time", str(timeout),
        "--write-out", "%{http_version}\t%{http_code}", url,
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=timeout + 2, check=False)
    except subprocess.TimeoutExpired:
        return url, "-", "-", "process timeout"
    except OSError as error:
        return url, "-", "-", str(error)
    fields = result.stdout.strip().split("\t")
    version, status = (fields + ["-", "-"])[:2]
    if result.returncode:
        detail = result.stderr.strip() or f"curl exit {result.returncode}"
    elif version != "2":
        detail = "HTTP/2 was not negotiated"
    elif not status.isdigit() or not 200 <= int(status) < 400:
        detail = "HTTP status outside 2xx/3xx"
    else:
        detail = "PASS"
    return url, version, status, detail


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", action="append", dest="urls", metavar="HTTPS_URL",
                        help="probe this URL; repeat to replace the ten defaults")
    parser.add_argument("--connect-timeout", type=int, default=5, metavar="SECONDS")
    parser.add_argument("--timeout", type=int, default=15, metavar="SECONDS")
    args = parser.parse_args()
    if not shutil.which("curl"):
        parser.error("curl is required")
    if args.connect_timeout < 1 or args.timeout < args.connect_timeout:
        parser.error("timeouts must be positive and total timeout >= connect timeout")
    urls = args.urls or DEFAULT_URLS
    for url in urls:
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
            parser.error(f"expected an HTTPS URL without credentials: {url}")
    with ThreadPoolExecutor(max_workers=min(4, len(urls))) as executor:
        outcomes = list(executor.map(
            lambda url: probe(url, args.connect_timeout, args.timeout), urls))
    for url, version, status, detail in outcomes:
        print(f"{detail}\tHTTP/{version}\tstatus={status}\t{url}")
    passed = sum(detail == "PASS" for _, _, _, detail in outcomes)
    print(f"{passed}/{len(outcomes)} passed")
    return 0 if passed == len(outcomes) else 1


if __name__ == "__main__":
    sys.exit(main())
