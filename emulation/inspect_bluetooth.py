#!/usr/bin/env python3
"""Read-only inspection of the guest Bluetooth UART; never claims phone pairing."""
import argparse
import json
from pathlib import Path
import socket

ROOT = Path(__file__).resolve().parent.parent
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--socket', type=Path, default=ROOT / 'artifacts/phase4/runs/features/control.qmp')
p.add_argument('--output', type=Path)
a = p.parse_args()
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
    s.settimeout(5)
    s.connect(str(a.socket))
    with s.makefile('rb') as f:
        json.loads(f.readline())
        sequence = 0
        def qmp(name, args=None):
            global sequence
            sequence += 1
            message = {'execute': name, 'id': sequence}
            if args is not None:
                message['arguments'] = args
            s.sendall((json.dumps(message) + '\n').encode())
            while True:
                r = json.loads(f.readline())
                if r.get('id') == sequence:
                    if 'error' in r:
                        raise RuntimeError(r['error'])
                    return r['return']
        qmp('qmp_capabilities')
        backends = qmp('query-chardev')
        attached = any(b.get('label') == 'smeg-bt' and b.get('frontend-open') for b in backends)
        counters = {}
        for prop in ['bluetooth-uart-rx-count','bluetooth-uart-sent-count','bluetooth-uart-overruns']:
            try:counters[prop] = qmp('qom-get', {'path':'/machine','property':prop})
            except RuntimeError:counters[prop] = None
        count = qmp('qom-get', {'path': '/machine', 'property': 'bluetooth-uart-tx-count'})
        prefix = qmp('qom-get', {'path': '/machine', 'property': 'bluetooth-uart-tx-prefix'})
        # Addresses established from HWALSetTransport and HWALTransportOpen.
        memory = {}
        for cmd in ['xp /100bx 0x03677c1c', 'xp /4wx 0x03677bf0']:
            memory[cmd] = qmp('human-monitor-command', {'command-line': cmd})
raw = bytes.fromhex(prefix)
commands = []
offset = 0
while offset + 4 <= len(raw) and raw[offset] == 1:
    length = raw[offset + 3]
    if offset + 4 + length > len(raw):
        break
    opcode = int.from_bytes(raw[offset + 1:offset + 3], 'little')
    commands.append({'offset': offset, 'opcode': f'0x{opcode:04x}',
                     'vendor_specific': opcode >> 10 == 0x3f,
                     'parameters_hex': raw[offset + 4:offset + 4 + length].hex()})
    offset += 4 + length
result = {'physical_car_access': False, 'phone_paired_to_guest': None, 'phone_pairing_status': 'not verified by this UART inspector',
          'uart_bridge_attached': bool(attached), 'uart_counters': counters,
          'transport': '/tyCo/1, logical UART1 / physical PSC1, IMMR0x80011100',
          'captured_tx_bytes': count, 'bounded_prefix_hex': prefix,
          'prefix_truncated': count > len(raw),
          'complete_h4_commands': commands, 'unparsed_prefix_hex': raw[offset:].hex(),
          'runtime': memory}
if a.output:
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
