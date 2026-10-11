#!/usr/bin/env python3
"""Namespace-only TCP peer and marked client, with deterministic bulk verification."""
import argparse
import hashlib
import json
import socket
import time

BLOCK = bytes(range(256)) * 4096
SIZE = 200 * 1024 * 1024
PORT = 18080


def server(ipv6=False):
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('2001:db8:1::2' if ipv6 else '192.0.2.2', PORT))
        listener.listen(16)
        print('ready', flush=True)
        while True:
            conn, _ = listener.accept()
            with conn:
                conn.settimeout(30)
                command = conn.recv(1)
                if command == b'B':
                    for _ in range(SIZE // len(BLOCK)):
                        conn.sendall(BLOCK)
                else:
                    conn.sendall(b'OK')


def client(mark, bulk=False, ipv6=False, expect_block=False):
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as conn:
        if mark:
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, mark)
        conn.settimeout(2 if expect_block else 30)
        address = '2001:db8:1::2' if ipv6 else '192.0.2.2'
        try:
            conn.connect((address, PORT))
        except (TimeoutError, OSError) as error:
            if expect_block:
                print('marked IPv6 SYN blocked:', error, flush=True)
                return
            raise
        assert not expect_block, 'marked IPv6 connection unexpectedly succeeded'
        if not bulk:
            conn.sendall(b'P')
            assert conn.recv(2) == b'OK'
            print(f'connection succeeded mark=0x{mark:x} ipv6={ipv6}', flush=True)
            return
        expected = hashlib.sha256()
        for _ in range(SIZE // len(BLOCK)):
            expected.update(BLOCK)
        digest = hashlib.sha256()
        received = 0
        start = time.monotonic()
        conn.sendall(b'B')
        while True:
            data = conn.recv(1024 * 1024)
            if not data:
                break
            digest.update(data)
            received += len(data)
        elapsed = time.monotonic() - start
        assert received == SIZE, (received, SIZE)
        assert digest.digest() == expected.digest(), 'bulk SHA256 mismatch'
        print(json.dumps({'bytes': received, 'sha256': digest.hexdigest(),
                          'seconds': round(elapsed, 3),
                          'MiB_per_second': round(received / 1048576 / elapsed, 2),
                          'mark': hex(mark)}), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['server', 'client'])
    parser.add_argument('--mark', type=lambda s: int(s, 0), default=0)
    parser.add_argument('--bulk', action='store_true')
    parser.add_argument('--ipv6', action='store_true')
    parser.add_argument('--expect-block', action='store_true')
    args = parser.parse_args()
    if args.mode == 'server':
        server(args.ipv6)
    else:
        client(args.mark, args.bulk, args.ipv6, args.expect_block)
