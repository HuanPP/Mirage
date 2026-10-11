#!/usr/bin/env python3
"""Read tcpdump's Ethernet pcap directly; independently verify wire checksums."""
import argparse
import json
import socket
import struct


def internet_sum(data):
    if len(data) % 2:
        data += b'\x00'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return total


def packets(path):
    with open(path, 'rb') as stream:
        header = stream.read(24)
        endian = {'d4c3b2a1': '<', 'a1b2c3d4': '>',
                  '4d3cb2a1': '<', 'a1b23c4d': '>'}[header[:4].hex()]
        assert struct.unpack(endian + 'I', header[20:24])[0] == 1, 'not Ethernet pcap'
        while True:
            record = stream.read(16)
            if not record:
                break
            _, _, captured, original = struct.unpack(endian + 'IIII', record)
            frame = stream.read(captured)
            assert captured == original
            if frame[12:14] == b'\x08\x00':
                yield frame[14:]


def options(data):
    result = {}
    while data:
        kind = data[0]
        if kind == 0:
            break
        if kind == 1:
            data = data[1:]
            continue
        length = data[1]
        assert length >= 2 and length <= len(data)
        assert kind not in result
        result[kind] = data[2:length]
        data = data[length:]
    return result


def verify(path, shape, scale, baseline=None):
    syns = []
    for p in packets(path):
        if p[9] != 6 or socket.inet_ntoa(p[12:16]) != '192.0.2.1':
            continue
        ihl = (p[0] & 15) * 4
        total = struct.unpack('!H', p[2:4])[0]
        tcp = p[ihl:total]
        if len(tcp) < 20 or tcp[13] & 0x12 != 2:
            continue
        assert ihl == 20
        assert internet_sum(p[:ihl]) == 65535, 'bad IP checksum'
        pseudo = p[12:20] + b'\x00\x06' + struct.pack('!H', len(tcp))
        tcp_valid = internet_sum(pseudo + tcp) == 65535
        if shape == 'macos':
            assert tcp_valid, 'bad rewritten TCP checksum on receiver'
        hlen = (tcp[12] >> 4) * 4
        win = struct.unpack('!H', tcp[14:16])[0]
        ipid = struct.unpack('!H', p[4:6])[0]
        opts = tcp[20:hlen]
        parsed = options(opts)
        assert parsed[3] == bytes([scale]), (parsed[3], scale)
        assert parsed[2] == struct.pack('!H', 1460)
        tsval = parsed[8][:4]
        if shape == 'macos':
            expected = bytes.fromhex('020405b4010303') + bytes([scale])
            expected += bytes.fromhex('0101080a') + tsval + bytes.fromhex('0000000004020000')
            assert opts == expected, opts.hex()
            assert total == 64 and hlen == 44 and ipid == 0 and win == 65535
        else:
            expected = bytes.fromhex('020405b40402080a') + tsval
            expected += bytes.fromhex('00000000010303') + bytes([scale])
            assert opts == expected, opts.hex()
            assert total == 60 and hlen == 40 and win != 65535
        assert p[1] == 0 and p[8] == 64 and p[6:8] == b'\x40\x00'
        syns.append({'options': opts.hex(), 'tsval': tsval.hex(), 'window': win,
                     'id': ipid, 'tcp_header': hlen, 'ip_length': total, 'wscale': scale,
                     'ip_checksum': 'valid',
                     'tcp_checksum': 'valid' if tcp_valid else 'partial (native veth offload)'})
    assert syns, 'no client SYN in capture'
    if baseline:
        with open(baseline) as stream:
            before = json.load(stream)
        assert all(p['options'][:16] == before['options'][:16] and
                   p['window'] == before['window'] and p['tcp_header'] == before['tcp_header']
                   for p in syns), 'unmarked/bypass shape changed'
    print(json.dumps(syns[0], sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('pcap')
    parser.add_argument('shape', choices=['native', 'macos'])
    parser.add_argument('scale', type=int)
    parser.add_argument('--baseline')
    args = parser.parse_args()
    verify(args.pcap, args.shape, args.scale, args.baseline)
