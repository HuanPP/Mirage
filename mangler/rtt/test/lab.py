#!/usr/bin/env python3
"""Lab traffic and capture validation; only called inside private namespaces.

T3 sleeps 160ms after each response before sending the next request. This
emulates the remote user's path; zero-latency local data alone cannot model it.
T5 reads scheduled EDT minus monotonic arrival from the optional BPF ring buffer.
Samples are real ACKs of one TCP flow, spaced 30ms and forced with QUICKACK.
This spacing limits monotonic clamping bias. Capture independently checks order.
"""
import hashlib
import json
import math
import os
import socket
import statistics
import struct
import sys
import time
import threading
import subprocess

SIZE = 50 * 1024 * 1024
BLOCK = bytes(range(256)) * 256
DIGEST = hashlib.sha256(BLOCK * (SIZE // len(BLOCK))).hexdigest()
PORT = 18449
MODES = os.environ.get("MIRRTT_CASES") or "BRJCUDPFQ"
UPLOAD = 20 * 1024 * 1024
PAIRS = 800
assert MODES and all(mode in "BRJCUDPFQ" for mode in MODES), "Unknown MIRRTT_CASES selector"


def offloads(mode):
    if mode in "DPFQ":
        state = "on" if mode in "DP" else "off"
        subprocess.run(["ethtool", "-K", "veth0", "tso", state, "gso", state, "gro", state], check=True, stdout=subprocess.DEVNULL)


def send_blocks(s, count):
    for _ in range(count // len(BLOCK)):
        s.sendall(BLOCK)


def digest_receive(s, count):
    digest = hashlib.sha256()
    while count:
        part = s.recv(min(count, 1024 * 1024))
        if not part:
            raise RuntimeError("unexpected EOF")
        digest.update(part)
        count -= len(part)
    return digest.hexdigest()


def info(s):
    b = s.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 232)
    u = lambda off: struct.unpack_from("=I", b, off)[0]
    return dict(rtt_ms=u(68) / 1000, rttvar_ms=u(72) / 1000,
                min_rtt_ms=u(148) / 1000, retrans=u(36),
                total_retrans=u(100), reordering=u(88))


def receive(s, n):
    b = bytearray()
    while len(b) < n:
        part = s.recv(n - len(b))
        if not part:
            raise RuntimeError("unexpected EOF")
        b.extend(part)
    return bytes(b)


def server(path):
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("10.77.0.2", PORT))
    listener.listen()
    rows = []
    for _ in MODES:
        s, addr = listener.accept()
        s.settimeout(90)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        mode = receive(s, 1).decode()
        row = dict(mode=mode, port=addr[1], samples=[])
        if mode in ("B", "U"):
            start = time.monotonic()
            for i in range(SIZE // len(BLOCK)):
                s.sendall(BLOCK)
                if i % 8 == 0:
                    row["samples"].append(info(s))
            digest = receive(s, 64).decode()
            row.update(sha256=digest, seconds=time.monotonic() - start)
            row["mbps"] = SIZE * 8 / row["seconds"] / 1e6
        elif mode == "R":
            times = []
            for _ in range(200):
                start = time.monotonic()
                s.sendall(b"r")
                assert receive(s, 1) == b"q"
                times.append((time.monotonic() - start) * 1000)
                row["samples"].append(info(s))
            row["app_ms"] = statistics.mean(times[50:])
        elif mode == "J":
            # No backpressure clock is used; outgoing bytes are paced naturally.
            for i in range(2200):
                s.sendall(b"j")
                time.sleep(.030)
            assert receive(s, 1) == b"d"
        elif mode == "C":
            for _ in range(30):
                s.sendall(b"c")
                assert receive(s, 1) == b"c"
                row["samples"].append(info(s))
                time.sleep(.003)
        elif mode in "DF":
            received = []
            reader = threading.Thread(target=lambda: received.append(digest_receive(s, UPLOAD)))
            reader.start()
            for i in range(SIZE // len(BLOCK)):
                s.sendall(BLOCK)
                if i % 8 == 0:
                    row["samples"].append(info(s))
            reader.join()
            row["upload_sha256"] = received[0]
            row["download_sha256"] = receive(s, 64).decode()
        elif mode in "PQ":
            up, down = hashlib.sha256(), hashlib.sha256()
            for _ in range(PAIRS):
                request = receive(s, 1024)
                up.update(request)
                response = request[::-1]
                s.sendall(response)
                down.update(response)
                row["samples"].append(info(s))
            row.update(upload_sha256=up.hexdigest(), download_sha256=down.hexdigest())
            assert receive(s, 1) == b"d"
        row["final"] = info(s)
        s.close()
        rows.append(row)
        with open(path, "w") as f:
            json.dump(rows, f)
    listener.close()


def client(path):
    rows = []
    for mode in MODES:
        offloads(mode)
        s = socket.socket()
        s.settimeout(90)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if mode not in ("C", "U"):
            s.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, 0x4d49)
        s.connect(("10.77.0.2", PORT))
        row = dict(mode=mode, port=s.getsockname()[1])
        if mode in "DPFQ":
            row["offload_features"] = subprocess.check_output(
                ["ethtool", "-k", "veth0"], text=True)
        # Immediate payload tests the handshake barrier against ACK overtaking.
        s.sendall(mode.encode())
        if mode in ("B", "U"):
            digest = hashlib.sha256()
            remaining = SIZE
            while remaining:
                b = s.recv(min(remaining, 1024 * 1024))
                assert b
                digest.update(b)
                remaining -= len(b)
            row["sha256"] = digest.hexdigest()
            s.sendall(row["sha256"].encode())
        elif mode == "R":
            for _ in range(200):
                assert receive(s, 1) == b"r"
                time.sleep(.160)
                s.sendall(b"q")
        elif mode == "J":
            for _ in range(2200):
                assert receive(s, 1) == b"j"
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
            s.sendall(b"d")
        elif mode == "C":
            for _ in range(30):
                assert receive(s, 1) == b"c"
                s.sendall(b"c")
        elif mode in "DF":
            writer = threading.Thread(target=send_blocks, args=(s, UPLOAD))
            writer.start()
            row["download_sha256"] = digest_receive(s, SIZE)
            writer.join()
            row["upload_sha256"] = hashlib.sha256(BLOCK * (UPLOAD // len(BLOCK))).hexdigest()
            s.sendall(row["download_sha256"].encode())
        elif mode in "PQ":
            request = BLOCK[:1024]
            up, down = hashlib.sha256(), hashlib.sha256()
            def upload_pairs():
                for _ in range(PAIRS):
                    s.sendall(request)
                    up.update(request)
            writer = threading.Thread(target=upload_pairs)
            writer.start()
            for _ in range(PAIRS):
                response = receive(s, 1024)
                assert response == request[::-1]
                down.update(response)
            writer.join()
            row.update(upload_sha256=up.hexdigest(), download_sha256=down.hexdigest())
            s.sendall(b"d")
        s.close()
        rows.append(row)
    with open(path, "w") as f:
        json.dump(rows, f)


def checksum(b):
    if len(b) & 1:
        b += b"\0"
    value = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while value >> 16:
        value = (value & 0xffff) + (value >> 16)
    return value


def packets(path):
    with open(path, "rb") as f:
        h = f.read(24)
        endian = "<" if h[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        nano = h[:4] in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        while True:
            h = f.read(16)
            if not h:
                break
            sec, fraction, length, _ = struct.unpack(endian + "IIII", h)
            b = f.read(length)
            if len(b) < 54 or b[12:14] != b"\x08\x00" or b[23] != 6:
                continue
            ihl = (b[14] & 15) * 4
            off = 14 + ihl
            if len(b) < off + 20:
                continue
            sport, dport, seq, ack = struct.unpack_from("!HHII", b, off)
            total = struct.unpack_from("!H", b, 16)[0]
            payload = total - ihl - (b[off + 12] >> 4) * 4
            tsecr = None
            if (b[off + 12] >> 4) * 4 >= 32 and b[off + 20:off + 24] == b"\x01\x01\x08\x0a":
                tsecr = struct.unpack_from("!I", b, off + 28)[0]
            valid = None
            if len(b) >= 14 + total:
                tcp_len = total - ihl
                pseudo = b[26:34] + struct.pack("!BBH", 0, 6, tcp_len)
                valid = checksum(pseudo + b[off:14 + total]) == 0xffff
            yield sec + fraction / (1e9 if nano else 1e6), sport, dport, seq, ack, b[off + 13], payload, tsecr, valid


def analyze(directory):
    with open(directory + "/server.json") as f:
        rows = {r["mode"]: r for r in json.load(f)}
    with open(directory + "/client.json") as f:
        clients = {r["mode"]: r for r in json.load(f)}
    synack, handshake, lastack, reorder, data_before = {}, {}, {}, {}, []
    all_ack, all_ts, regress_ack, regress_ts, checksums = {}, {}, {}, {}, {}
    for ts, sport, dport, seq, ack, flags, payload, tsecr, valid in packets(directory + "/capture.pcap"):
        if sport == PORT and flags & 0x12 == 0x12:
            synack.setdefault(dport, ts)
        if dport == PORT and flags & 0x10 and not flags & 0x02:
            if not flags & 0x04:
                if sport in all_ack and ((ack - all_ack[sport]) & 0xffffffff) > 0x80000000:
                    regress_ack[sport] = regress_ack.get(sport, 0) + 1
                all_ack[sport] = ack
                if tsecr is not None:
                    if sport in all_ts and ((tsecr - all_ts[sport]) & 0xffffffff) > 0x80000000:
                        regress_ts[sport] = regress_ts.get(sport, 0) + 1
                    all_ts[sport] = tsecr
                good, bad = checksums.get(sport, (0, 0))
                checksums[sport] = good + (valid is True), bad + (valid is not True)
            if payload == 0 and sport in synack:
                handshake.setdefault(sport, (ts - synack[sport]) * 1000)
            if payload and sport not in handshake and sport in synack:
                data_before.append(sport)
            if payload == 0 and flags == 0x10:
                if sport in lastack and ((ack - lastack[sport]) & 0xffffffff) > 0x80000000:
                    reorder[sport] = reorder.get(sport, 0) + 1
                lastack[sport] = ack
    assert not data_before, ("payload overtook handshake", data_before)
    assert not reorder, ("ACK reordering", reorder)
    if "B" in rows:
        analyze_bulk(rows, clients, handshake)
    if "R" in rows:
        analyze_response(rows["R"])
    if "C" in rows:
        control = rows["C"]["final"]["rtt_ms"]
        assert control < 2, ("T4", control)
        print("T4 unmarked srtt: %.3f ms" % control)
    if "J" in rows:
        analyze_jitter(directory, rows["J"])
    if "U" in rows and "B" in rows:
        assert rows["U"]["sha256"] == DIGEST
        print("T6 50 MiB throughput shaped=%.3f Mbps unmarked=%.3f Mbps" % (rows["B"]["mbps"], rows["U"]["mbps"]))
    for mode in "DPFQ":
        if mode not in rows:
            continue
        row, client_row = rows[mode], clients[mode]
        port = row["port"]
        srtt = statistics.median([s["rtt_ms"] for s in row["samples"][len(row["samples"]) // 2:]])
        minimum = row["final"]["min_rtt_ms"]
        # min_rtt is the leak detector: any fresh ACK/TSecr on an undelayed
        # segment collapses it toward the 0 ms lab path. The srtt ceiling is
        # looser for the overlapping-pairs modes (P, Q): there the shaped client
        # kernel's delayed ACK (40 ms minimum) stacks on top of the shaped delay,
        # exactly as it would for a genuine client 160 ms away.
        ceiling = 184 if mode in "DF" else 200
        assert minimum >= 136 and 136 <= srtt <= ceiling, ("T8 RTT", mode, minimum, srtt)
        for direction in ("upload", "download"):
            assert row[direction + "_sha256"] == client_row[direction + "_sha256"], (mode, direction)
        assert regress_ack.get(port, 0) == regress_ts.get(port, 0) == 0, ("T8 regressions", mode, regress_ack.get(port), regress_ts.get(port))
        good, bad = checksums[port]
        assert good > 0 and bad == 0, ("T8 checksums", mode, good, bad)
        with open(directory + "/samples.jsonl") as f:
            max_gso = max((e["GSO"] for line in f for e in [json.loads(line)]
                           if socket.ntohs(e["Key"]["Sport"]) == port), default=0)
        if mode == "D":
            assert max_gso > 1, ("T8 missing GSO input", max_gso)
        print("T8 %s offloads=%s min_rtt=%.3f ms srtt=%.3f ms ACK regressions=0 TSecr regressions=0 checksums=%d valid/0 invalid max_GSO_segs=%d; both SHA256 correct" % ("20/50 MiB duplex" if mode in "DF" else "800 overlapping pairs, no sleep", "on" if mode in "DP" else "off", minimum, srtt, good, max_gso))


def analyze_bulk(rows, clients, handshake):
    b = rows["B"]
    hs = handshake[b["port"]]
    assert 140 <= hs <= 180, ("T1", hs)
    print("T1 handshake SYN-ACK -> final ACK: %.3f ms; no early payload" % hs)
    srtt = statistics.median([s["rtt_ms"] for s in b["samples"][len(b["samples"]) // 2:]])
    assert 136 <= srtt <= 184, ("T2", srtt)
    assert b["final"]["min_rtt_ms"] >= 136, ("T2 min_rtt", b["final"])
    assert b["sha256"] == clients["B"]["sha256"] == DIGEST
    retrans = max(s["total_retrans"] for s in b["samples"] + [b["final"]])
    # A few timer-driven spurious retransmissions are possible with correlated
    # jitter even without queue loss. "Near zero" means at most 0.02% of the
    # MSS-sized transfer, and the count is always reported rather than hidden.
    assert retrans / math.ceil(SIZE / 1460) <= .0002, ("T2 retrans", retrans)
    print("T2 50 MiB srtt: %.3f ms; sha256=%s; retrans=%d; ACK reorder=0; final=%s" % (srtt, DIGEST, retrans, json.dumps(b["final"])))


def analyze_response(r):
    tcp = statistics.mean([s["rtt_ms"] for s in r["samples"][50:]])
    assert abs(r["app_ms"] - tcp) / tcp <= .15, ("T3", r["app_ms"], tcp)
    assert r["final"]["min_rtt_ms"] >= 136, ("T3 min_rtt", r["final"])
    print("T3 200 response-triggered requests, 160ms user-path sleep: app=%.3f ms TCP=%.3f ms min_rtt=%.3f ms difference=%.2f%%" % (r["app_ms"], tcp, r["final"]["min_rtt_ms"], abs(r["app_ms"] - tcp) / tcp * 100))


def analyze_jitter(directory, row):
    events = []
    with open(directory + "/samples.jsonl") as f:
        for line in f:
            e = json.loads(line)
            if e["Kind"] == 2 and socket.ntohs(e["Key"]["Sport"]) == row["port"]:
                events.append(e)
    assert len(events) >= 2000, ("T5 samples", len(events))
    events = events[100:2100] if len(events) >= 2100 else events[:2000]
    values = [(e["Edt"] - e["Now"]) / 1e6 for e in events]
    mean, sd = statistics.mean(values), statistics.pstdev(values)
    a, c = values[:-1], values[1:]
    am, cm = statistics.mean(a), statistics.mean(c)
    rho = sum((x - am) * (y - cm) for x, y in zip(a, c)) / math.sqrt(sum((x - am) ** 2 for x in a) * sum((y - cm) ** 2 for y in c))
    assert 155 <= mean <= 165 and 6 <= sd <= 10 and .8 <= rho <= 1, ("T5", mean, sd, rho)
    assert all(x["Edt"] <= y["Edt"] for x, y in zip(events, events[1:]))
    print("T5 %d real ACK EDT samples: mean=%.3f ms stddev=%.3f ms lag1=%.4f; scheduled/captured reorder=0" % (len(values), mean, sd, rho))


if __name__ == "__main__":
    {"server": server, "client": client, "analyze": analyze}[sys.argv[1]](sys.argv[2])
