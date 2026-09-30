"""Explicit live-network HTTP/3 probes; remote QUIC v2 support is unknown."""

import argparse
import hashlib
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", required=True, type=Path)
    parser.add_argument("--version", choices=["v1", "v2"], required=True)
    parser.add_argument("--timeout-ms", type=int, default=10000)
    parser.add_argument("--expect-status", type=int, default=200)
    parser.add_argument("--contains", help="optional UTF-8 body marker")
    parser.add_argument("--sha256", help="optional expected body SHA-256")
    parser.add_argument("urls", nargs="+")
    args = parser.parse_args()
    if not 1 <= args.timeout_ms <= 3600000:
        parser.error("--timeout-ms must be 1..3600000")
    failed = False
    for url in args.urls:
        try:
            result = subprocess.run([
                str(args.client.resolve()), "--version", args.version,
                "--timeout-ms", str(args.timeout_ms), url], capture_output=True,
                timeout=args.timeout_ms / 1000 + 5)
            digest = hashlib.sha256(result.stdout).hexdigest()
            valid = (result.returncode == 0 and
                     f"HTTP/3 {args.expect_status}\n".encode() in result.stderr and
                     (not args.contains or args.contains.encode() in result.stdout) and
                     (not args.sha256 or args.sha256 == digest))
            print(f"{'PASS' if valid else 'FAIL'} requested={args.version} {url} "
                  f"exit={result.returncode} bytes={len(result.stdout)} sha256={digest}")
            print(result.stderr.decode(errors="replace"), file=sys.stderr, end="")
            failed |= not valid
        except subprocess.TimeoutExpired:
            print(f"FAIL requested={args.version} {url}: process timeout", file=sys.stderr)
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
