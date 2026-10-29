#!/usr/bin/env python3
"""Summarize the latest bridge session without exposing pairing key material."""
import argparse
from collections import Counter
import json
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('log', type=Path)
p.add_argument('--output', type=Path)
p.add_argument('--session', type=int, default=-1, help='Session index; -1 is latest, -2 previous')
a = p.parse_args()
rows = [json.loads(line) for line in a.log.read_text().splitlines() if line.strip()]
starts = [i for i, row in enumerate(rows) if row['event'] == 'listening'] or [0]
try:
    index = a.session if a.session >= 0 else len(starts) + a.session
    if index < 0:
        raise IndexError
    start = starts[index]
except IndexError:
    p.error('Session index out of range')
rows = rows[start:starts[index + 1] if index + 1 < len(starts) else len(rows)]
commands, physical_events, completions = Counter(), Counter(), []
links, discoveries, failures, statuses, remote_names, encryption_changes = [], [], [], [], [], []
names = {1: 'inquiry_complete', 2: 'inquiry_result', 3: 'connection_complete',
         4: 'connection_request', 5: 'disconnection_complete', 6: 'authentication_complete',
         0x17: 'link_key_request', 0x18: 'link_key_notification', 0x22: 'inquiry_result_rssi',
         0x2f: 'extended_inquiry_result', 0x31: 'io_capability_request',
         0x33: 'user_confirmation_request', 0x36: 'simple_pairing_complete'}
for row in rows:
    if row['event'] == 'error':
        failures.append({'type': row.get('type'), 'message': row.get('message')})
    if row['event'] != 'packet':
        continue
    if row.get('key_material') == 'redacted':
        if row['direction'] == 'guest' and row.get('opcode'):
            commands[row['opcode']] += 1
        if row['direction'] == 'radio' and row.get('event_code') is not None:
            event = row['event_code']
            physical_events[names.get(event, f'0x{event:02x}')] += 1
        continue
    packet = bytes.fromhex(row['hex'])
    if row['direction'] == 'guest' and packet[0] == 1:
        commands[f'0x{int.from_bytes(packet[1:3], "little"):04x}'] += 1
    if row['direction'] != 'radio' or packet[0] != 4 or len(packet) < 3:
        continue
    event = packet[1]
    physical_events[names.get(event, f'0x{event:02x}')] += 1
    if event == 0x0e and len(packet) >= 7:
        completions.append({'opcode': f'0x{int.from_bytes(packet[4:6], "little"):04x}',
                            'status': packet[6]})
    if event == 0x0f and len(packet) >= 7:
        statuses.append({'opcode': f'0x{int.from_bytes(packet[5:7], "little"):04x}',
                         'status': packet[3]})
    if event == 7 and len(packet) >= 10:
        result = {'status': packet[3],
                  'address': ':'.join(f'{b:02X}' for b in packet[4:10][::-1])}
        if packet[3] == 0:
            result['name'] = packet[10:].split(b'\0', 1)[0].decode('utf-8', 'replace')
        remote_names.append(result)
    if event == 8 and len(packet) >= 7:
        encryption_changes.append({'status': packet[3],
                                   'handle': int.from_bytes(packet[4:6], 'little'),
                                   'enabled': packet[6]})
    if event in (2, 0x22, 0x2f) and len(packet) >= 10 and packet[3]:
        discoveries.append({'event': names[event],
                            'first_address': ':'.join(f'{b:02X}' for b in packet[4:10][::-1])})
    if event == 3 and len(packet) >= 14:
        links.append({'status': packet[3], 'handle': int.from_bytes(packet[4:6], 'little'),
                      'address': ':'.join(f'{b:02X}' for b in packet[6:12][::-1]),
                      'link_type':packet[12], 'encryption_enabled':packet[13]})
report = {'log': str(a.log), 'mode': rows[0].get('mode') if rows else None,
          'radio_enabled': rows[0].get('radio_enabled') if rows else None,
          'physical_car_access': False, 'commands': dict(commands),
          'physical_event_counts': dict(physical_events),
          'physical_command_completions': completions,
          'physical_command_statuses': statuses, 'physical_remote_names': remote_names,
          'physical_encryption_changes': encryption_changes,
          'legacy_name_workarounds': [r for r in rows if r['event'].startswith('legacy_name_')],
          'existing_host_bond_reuse': [r for r in rows if r['event'] in ('existing_host_bond_reused','existing_bond_reply_complete')],
          'discoveries': discoveries, 'physical_connections': links,
          'guest_pairing_confirmed': bool(physical_events['link_key_notification']),
          'guest_network_access_verified': False, 'bridge_errors': failures,
          'session_disconnected': any(r['event'] == 'disconnected' for r in rows),
          'virtual_events_are_not_RF_proof': True}
text = json.dumps(report, indent=2) + '\n'
if a.output:
    a.output.write_text(text)
print(text, end='')
