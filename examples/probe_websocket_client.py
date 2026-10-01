#!/usr/bin/env python3
"""Run the eventloop WebSocket client against each URL and report every result."""

import argparse
import subprocess
import sys

DEFAULT_URLS = [
    "wss://echo.websocket.org/",
    "wss://ws.postman-echo.com/raw",
    "wss://ws.ifelse.io/",
    "wss://echo.rapidtoolset.com/ws",
    "wss://echo-websocket.fly.dev/",
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", default="./build/websocket_client")
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("urls", nargs="*", help="URLs to probe (defaults to five public endpoints)")
    args = parser.parse_args()
    urls = args.urls or DEFAULT_URLS
    failures = 0
    for index, url in enumerate(urls):
        message = f"eventloop-probe-{index}"
        try:
            result = subprocess.run(
                [args.client, url, message], capture_output=True, text=True,
                timeout=args.timeout, check=False,
            )
            passed = result.returncode == 0 and result.stdout.strip() == f"echo: {message}"
            detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        except subprocess.TimeoutExpired:
            passed = False
            detail = f"timeout after {args.timeout:g}s"
        except OSError as error:
            passed = False
            detail = str(error)
        print(f"{'PASS' if passed else 'FAIL'} {url}: {detail}", flush=True)
        failures += not passed
    print(f"{len(urls) - failures}/{len(urls)} passed")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
