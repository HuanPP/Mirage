#!/usr/bin/env python3
"""Open one marked IPv4 TCP connection. Used by install-vps.sh --status."""
import socket
import sys

if len(sys.argv) != 4:
    sys.stderr.write("usage: status-connect.py <host> <port> <mark>\n")
    sys.exit(2)

host = sys.argv[1]
port = int(sys.argv[2])
mark = int(sys.argv[3], 0)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, mark)
    sock.settimeout(5)
    sock.connect((host, port))
finally:
    sock.close()
