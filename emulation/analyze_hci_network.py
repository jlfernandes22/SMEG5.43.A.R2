#!/usr/bin/env python3
"""Read-only, payload-minimizing evidence of BNEP and DHCP over a real HCI session."""
import argparse
import ipaddress
import json
from pathlib import Path


def analyze(rows):
    start = max((i for i, r in enumerate(rows) if r['event'] == 'listening'), default=0)
    rows = rows[start:]
    pending, requests, channels = {}, {}, set()
    setups, leases = [], []
    counts = {'guest': 0, 'radio': 0}
    for row in rows:
        if row['event'] != 'packet' or 'hex' not in row:
            continue
        packet = bytes.fromhex(row['hex'])
        if len(packet) < 5 or packet[0] != 2:
            continue
        direction = row['direction']
        if direction not in counts:
            continue
        other = 'guest' if direction == 'radio' else 'radio'
        flags = int.from_bytes(packet[1:3], 'little')
        handle, boundary = flags & 0xfff, (flags >> 12) & 3
        key = (direction, handle)
        payload = packet[5:]
        if len(payload) != int.from_bytes(packet[3:5], 'little'):
            continue
        if boundary in (0, 2):
            pending[key] = bytearray(payload)
        elif boundary == 1 and key in pending:
            pending[key].extend(payload)
        else:
            continue
        data = pending[key]
        if len(data) < 4:
            continue
        length, cid = int.from_bytes(data[:2], 'little'), int.from_bytes(data[2:4], 'little')
        if len(data) < length + 4:
            continue
        del pending[key]
        if len(data) != length + 4:
            continue
        data = bytes(data[4:])
        if cid == 1:
            offset = 0
            while offset + 4 <= len(data):
                code, ident = data[offset:offset + 2]
                n = int.from_bytes(data[offset + 2:offset + 4], 'little')
                params = data[offset + 4:offset + 4 + n]
                offset += 4 + n
                if len(params) != n:
                    break
                if code == 2 and len(params) == 4:
                    psm, source = int.from_bytes(params[:2], 'little'), int.from_bytes(params[2:], 'little')
                    requests[(direction, handle, ident)] = (psm, source)
                elif code == 3 and len(params) == 8:
                    req = requests.get((other, handle, ident))
                    destination = int.from_bytes(params[:2], 'little')
                    result = int.from_bytes(params[4:6], 'little')
                    if req and req[0] == 15 and result == 0:
                        channels.add((direction, handle, req[1]))
                        channels.add((other, handle, destination))
            continue
        if (direction, handle, cid) not in channels or not data:
            continue
        kind = data[0] & 0x7f
        if kind == 1:
            if len(data) == 7 and data[1:3] == b'\x01\x02':
                setups.append({'direction': direction, 'kind': 'request',
                               'destination_uuid': data[3:5].hex(), 'source_uuid': data[5:7].hex()})
            elif len(data) == 4 and data[1] == 2:
                setups.append({'direction': direction, 'kind': 'response',
                               'result': int.from_bytes(data[2:4], 'big')})
            continue
        sizes = {0: 15, 2: 3, 3: 9, 4: 9}
        size = sizes.get(kind)
        if size is None or data[0] & 0x80 or len(data) < size:
            continue  # extension headers need a separate parser
        counts[direction] += 1
        if data[size - 2:size] != b'\x08\x00':
            continue
        ip = data[size:]
        if len(ip) < 28 or ip[0] >> 4 != 4 or ip[9] != 17:
            continue
        ihl = (ip[0] & 15) * 4
        udp = ip[ihl:]
        if len(udp) < 8 or {int.from_bytes(udp[:2], 'big'), int.from_bytes(udp[2:4], 'big')} != {67, 68}:
            continue
        bootp = udp[8:]
        if len(bootp) < 240 or bootp[236:240] != b'\x63\x82\x53\x63':
            continue
        options, pos = {}, 240
        while pos < len(bootp):
            opt = bootp[pos]; pos += 1
            if opt == 255:
                break
            if opt == 0:
                continue
            if pos >= len(bootp):
                break
            n = bootp[pos]; pos += 1
            if pos + n > len(bootp):
                break
            options[opt] = bootp[pos:pos + n]; pos += n
        msg = options.get(53, b'\0')[0]
        entry = {'direction': direction, 'message_type': msg,
                 'message': {1:'discover', 2:'offer', 3:'request', 5:'ack', 6:'nak'}.get(msg, 'other'),
                 'transaction': bootp[4:8].hex(), 'assigned_ip': str(ipaddress.IPv4Address(bootp[16:20]))}
        for option, name in [(1, 'subnet_mask'), (3, 'router'), (54, 'server')]:
            if len(options.get(option, b'')) >= 4:
                entry[name] = str(ipaddress.IPv4Address(options[option][:4]))
        leases.append(entry)
    acks = [r for r in leases if r['direction'] == 'radio' and r['message_type'] == 5]
    return {'physical_car_access': False, 'evidence': 'Actual forwarded radio ACL frames',
            'bnep_setups': setups, 'bnep_data_packets': counts, 'dhcp': leases,
            'guest_pan_ip_configuration_observed': bool(acks),
            'external_internet_reachability_verified': False,
            'note': 'DHCP/PAN evidence does not prove an external website is reachable.'}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('log', type=Path)
    p.add_argument('--output', type=Path)
    args = p.parse_args()
    report = analyze([json.loads(line) for line in args.log.read_text().splitlines() if line.strip()])
    result = json.dumps(report, indent=2) + '\n'
    if args.output:
        args.output.write_text(result)
    print(result, end='')
