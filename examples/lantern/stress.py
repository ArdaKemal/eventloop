#!/usr/bin/env python3
"""Seek storm for Lantern: what a crowd of video players does to a server.

Starts lantern with a fresh data directory, uploads a video in chunks, then
runs many viewers at once. Each viewer requests random byte ranges over
HTTP/1.1 (cleartext and TLS), HTTP/2, or HTTP/3 and drops half of them in
the middle of the body, the way a browser does when the viewer seeks. More
uploads run at the same time. Completed ranges must match the file byte for
byte, the server must keep answering, and Ctrl-C must stop it cleanly.

usage: stress.py LANTERN_BINARY [--viewers N] [--requests N] [--size MIB]
Set LANTERN_WRAPPER (for example "valgrind --error-exitcode=99") to run the
server under a tool. Needs curl with HTTP/3 support.
"""

import argparse
import concurrent.futures
import json
import os
import random
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import time


def free_port():
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


def curl(*args, data=None):
    command = ['curl', '-4sSk', '--max-time', '60', *args]
    return subprocess.run(command, input=data, capture_output=True)


class Server:
    def __init__(self, binary, root):
        self.port = free_port()
        self.http_port = free_port()
        self.base = f'https://localhost:{self.port}'
        self.plain = f'http://localhost:{self.http_port}'
        wrapper = shlex.split(os.environ.get('LANTERN_WRAPPER', ''))
        self.log = open(os.path.join(root, 'server.log'), 'w')
        self.process = subprocess.Popen(
            [*wrapper, binary, '--data', os.path.join(root, 'data'), '--port', str(self.port),
             '--http-port', str(self.http_port), '--http3'],
            stdout=self.log, stderr=subprocess.STDOUT)
        for _ in range(200):
            if curl(f'{self.base}/api/videos').returncode == 0:
                return
            time.sleep(0.05)
        raise SystemExit('lantern did not start')

    def url(self, transport, path):
        return (self.plain if transport == 'http1-plain' else self.base) + path

    def stop(self):
        self.process.send_signal(signal.SIGINT)
        started = time.monotonic()
        code = self.process.wait(timeout=60)
        return code, time.monotonic() - started


TRANSPORTS = {
    'http1-plain': ['--http1.1'],
    'http1-tls': ['--http1.1'],
    'http2': ['--http2'],
    'http3': ['--http3-only'],
}


def upload(server, content, chunk_transports):
    fields = {'size': len(content), 'type': 'video/webm', 'duration': 60000,
              'title': 'Stress clip', 'description': '', 'channel': 'stress'}
    args = [arg for key, value in fields.items() for arg in ('--data-urlencode', f'{key}={value}')]
    created = curl('-X', 'POST', *args, f'{server.base}/api/uploads')
    state = json.loads(created.stdout)
    received = 0
    for index in range(0, len(content), state['chunk']):
        transport = chunk_transports[index // state['chunk'] % len(chunk_transports)]
        part = content[index:index + state['chunk']]
        reply = curl(*TRANSPORTS[transport], '-X', 'PUT', '--data-binary', '@-',
                     server.url(transport, f'/api/uploads/{state["id"]}?offset={received}'), data=part)
        received = json.loads(reply.stdout)['received']
        assert received == index + len(part), (transport, reply.stdout)
    published = curl('-X', 'POST', f'{server.base}/api/uploads/{state["id"]}/publish', '-w', '%{http_code}')
    assert published.stdout.endswith(b'201'), published.stdout
    return state['id']


def viewer(server, video, content, requests, seed):
    rng = random.Random(seed)
    counts = {'complete': 0, 'dropped': 0}
    for _ in range(requests):
        transport = rng.choice(list(TRANSPORTS))
        first = rng.randrange(len(content))
        last = min(len(content) - 1, first + rng.randrange(1, 4 * 1024 * 1024))
        args = [*TRANSPORTS[transport], '-r', f'{first}-{last}', server.url(transport, f'/v/{video}')]
        if rng.random() < 0.5:
            # Seek away mid-body: slow the transfer, then give up on it.
            curl('--limit-rate', '2M', '--max-time', f'{rng.uniform(0.02, 0.3):.2f}', *args)
            counts['dropped'] += 1
            continue
        result = curl('-w', '\n%{http_code}', *args)
        body, _, status = result.stdout.rpartition(b'\n')
        assert status == b'206', (transport, status, result.returncode, result.stderr)
        assert body == content[first:last + 1], (transport, first, last, len(body))
        counts['complete'] += 1
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('binary')
    parser.add_argument('--viewers', type=int, default=24)
    parser.add_argument('--requests', type=int, default=40)
    parser.add_argument('--size', type=int, default=64, help='video size in MiB')
    options = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix='lantern-stress-') as root:
        server = Server(options.binary, root)
        content = os.urandom(options.size * 1024 * 1024)
        started = time.monotonic()
        video = upload(server, content, list(TRANSPORTS))
        print(f'uploaded {options.size} MiB over every transport in {time.monotonic() - started:.1f} s')

        started = time.monotonic()
        totals = {'complete': 0, 'dropped': 0}
        with concurrent.futures.ThreadPoolExecutor(options.viewers + 2) as pool:
            uploads = [pool.submit(upload, server, os.urandom(24 * 1024 * 1024), [transport])
                       for transport in ('http2', 'http3')]
            viewers = [pool.submit(viewer, server, video, content, options.requests, seed)
                       for seed in range(options.viewers)]
            for future in viewers:
                for key, value in future.result().items():
                    totals[key] += value
            for future in uploads:
                future.result()
        print(f'{totals["complete"]} ranges verified, {totals["dropped"]} dropped mid-body, '
              f'2 concurrent uploads, in {time.monotonic() - started:.1f} s')

        listing = json.loads(curl(f'{server.base}/api/videos').stdout)
        assert len(listing['videos']) == 3, listing
        code, seconds = server.stop()
        print(f'server exit {code} after {seconds:.2f} s')
        if code != 0:
            print(open(os.path.join(root, 'server.log')).read()[-4000:])
            return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
