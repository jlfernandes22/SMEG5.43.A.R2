#!/usr/bin/env python3
"""Short real-controller name-request comparison; no pairing or key changes."""
import argparse
import json
from pathlib import Path
import socket
import struct
import time
from hci_peer import bluetooth_peer, peer_bytes

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--peer', type=bluetooth_peer, required=True, help='Explicit phone Bluetooth address; no default')
p.add_argument('--radio-fd', type=int, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
radio = socket.socket(fileno=a.radio_fd)
radio.settimeout(1)
report = {'physical_car_access': False, 'pairing_requested': False,
          'explicit_peer_configured': True, 'transactions': []}
started = time.monotonic()
phase = 'cold'

def command(opcode, params=b'', remote_name=False):
    row = {'phase': phase, 'opcode': f'0x{opcode:04x}', 'parameters': params.hex(), 'events': []}
    report['transactions'].append(row)
    packet = b'\x01' + struct.pack('<HB', opcode, len(params)) + params
    radio.sendall(packet)
    deadline = time.monotonic() + (9 if remote_name else 3)
    while time.monotonic() < deadline:
        try:
            event = radio.recv(65540)
        except socket.timeout:
            continue
        if event[:2] in (b'\x04\x18', b'\x04\x15'):
            row['events'].append({'event': event[1], 'key_material': 'redacted'})
            continue
        row['events'].append({'hex': event.hex()})
        if event[:2] == b'\x04\x0e' and len(event) >= 7 and int.from_bytes(event[4:6], 'little') == opcode:
            row['status'] = event[6]
            break
        if event[:2] == b'\x04\x0f' and len(event) >= 7 and int.from_bytes(event[5:7], 'little') == opcode:
            row['status'] = event[3]
            if event[3] or not remote_name:
                break
        if remote_name and event[:2] == b'\x04\x07' and len(event) >= 10:
            row['name_status'] = event[3]
            if event[3] == 0:
                row['name'] = event[10:].split(b'\0', 1)[0].decode('utf-8', 'replace')
            break
    else:
        row['timed_out'] = True
    a.output.write_text(json.dumps(report, indent=2) + '\n')
    a.output.chmod(0o600)
    print(json.dumps({k: v for k, v in row.items() if k != 'events'}), flush=True)
    return row

try:
    command(0x0c03)
    command(0x1001)
    command(0x1003)
    address = peer_bytes(a.peer)
    # Cold request with an explicitly invalid/unused clock-offset hint.
    first = command(0x0419, address + b'\x01\0\0\0', remote_name=True)
    if first.get('name_status') == 0:
        # Replay only the observed standard initialization settings. Never
        # replay pairing, connections, link keys, ACL or vendor RAM commands.
        log = a.output.with_name('hci.jsonl')
        rows = [json.loads(line) for line in log.read_text().splitlines()]
        begin = max(i for i, row in enumerate(rows) if row['event'] == 'listening')
        allowed = {0x0c05, 0x0c0a, 0x0c13, 0x0c16, 0x0c18, 0x0c19,
                   0x0c1a, 0x0c20, 0x0c22, 0x0c24, 0x0c26, 0x0c33,
                   0x1001, 0x1005, 0x1009}
        settings = []
        for row in rows[begin:]:
            if row.get('direction') != 'guest' or row['event'] != 'packet':
                continue
            packet = bytes.fromhex(row['hex'])
            if packet[0] != 1:
                continue
            opcode = int.from_bytes(packet[1:3], 'little')
            if opcode == 0x0401:
                break
            if opcode in allowed:
                settings.append((opcode, packet[4:]))
        report['replayed_settings'] = len(settings)
        def prefix(n):
            global phase
            phase = f'native_prefix_{n}'
            command(0x0c03)
            for opcode, params in settings[:n]:
                command(opcode, params)
            return command(0x0419, address + b'\x01\0\0\0', remote_name=True)
        end = prefix(len(settings)) if settings else first
        if end.get('status') == 0x0c:
            low, high = 0, len(settings)
            while high-low > 1 and time.monotonic()-started < 38:
                middle = (low+high)//2
                trial = prefix(middle)
                if trial.get('status') == 0x0c:
                    high = middle
                elif trial.get('name_status') == 0:
                    low = middle
                else:
                    break
            report['prefix_boundary'] = {'last_good': low, 'first_bad': high,
                                         'candidate_opcode': f'0x{settings[high-1][0]:04x}',
                                         'candidate_parameters': settings[high-1][1].hex()}
    else:
        command(0x041a, address)  # Cancel an outstanding procedure, if any.
        # Explicit experiment, not an assertion that the old guest supports SSP.
        command(0x0c56, b'\x01')
        command(0x0419, address + b'\x01\0\0\0', remote_name=True)
finally:
    phase = 'restore'
    command(0x0c03)
    radio.close()
