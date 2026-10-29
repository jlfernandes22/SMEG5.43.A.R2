#!/usr/bin/env python3
"""Inspect/control this project's live QEMU through its local QMP socket."""
import argparse
import json
import re
import socket
import time
from pathlib import Path

root = Path(__file__).resolve().parent.parent
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--socket', type=Path,
               help='Explicit QMP socket; otherwise prefer the stable features UI, then the original UI')
p.add_argument('--screenshot', type=Path)
p.add_argument('--settle', type=float, default=3.0,
               help='Seconds to allow native async UI transitions before an input+screenshot (default3)')
p.add_argument('--click', nargs=2, type=int, metavar=('X', 'Y'))
p.add_argument('--info-mice', action='store_true')
p.add_argument('--status', action='store_true')
p.add_argument('--touch-calibration', action='store_true')
p.add_argument('--touch-state', action='store_true')
p.add_argument('--usb-status', action='store_true')
p.add_argument('--panel', choices=['menu', 'src', 'cheat', 'versions', 'media', 'nav', 'config', 'drive', 'web', 'telephone', 'climate'],
               help='Bench front-panel key through the original MCU keyboard protocol')
p.add_argument('--car-fmux', action='store_true',
               help='Use the captured car FMUX mapping; app shortcuts use the native application selector')
p.add_argument('--key', nargs=2, type=lambda x: int(x, 0), metavar=('ID', 'STATUS'),
               help='Original MCU key ID00..44 and status01..0a (emulator only)')
p.add_argument('--temperature', type=float, help='Simulated external Celsius temperature, -40..85 in0.5 degree steps')
p.add_argument('--temperature-unknown', action='store_true')
p.add_argument('--clock-live', action='store_true', help='Native clock follows the QEMU RTC (host Lisbon time in features launcher)')
p.add_argument('--eco', choices=['off', 'on'], help='Simulated ECU Stop/Start status only')
p.add_argument('--notify', action='store_true', help='Also request the original native Eco status popup')
p.add_argument('--esp', choices=['off', 'on'], help='Ordinary simulated traction/ESP state and native notification; not Grip Control')
p.add_argument('--parking', choices=['active', 'standby', 'off'], help='Simulated parking ECU status fixture')
p.add_argument('--traction', choices=['off', 'normal', 'snow', 'mud', 'sand'],
               help='Simulated ASR+ ECU mode only')
p.add_argument('--vehicle-network', choices=['healthy', 'economy', 'unknown'], help='Simulated MCU vehicle-network status; preserves native phase bits0x60')
p.add_argument('--stationary', action='store_true', help='Simulated valid vehicle speed0')
p.add_argument('--functions-available', action='store_true', help='Simulated vehicle function-availability status1')
p.add_argument('--quit', action='store_true')
a = p.parse_args()
if a.key and not (0 <= a.key[0] <= 0x44 and 1 <= a.key[1] <= 0x0a):
    p.error('--key requires ID00..44 and status01..0a')
if a.temperature is not None and not (-40 <= a.temperature <= 85 and (a.temperature * 2).is_integer()):
    p.error('--temperature requires -40..85 in0.5 degree steps')
if a.temperature is not None and a.temperature_unknown:
    p.error('choose a temperature or unknown')
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(5)
choices = [a.socket] if a.socket else [root / 'artifacts/phase4/runs/features/control.qmp',
                                     root / 'artifacts/phase3/interactive.qmp']
for candidate in choices:
    try:
        s.connect(str(candidate))
        break
    except (FileNotFoundError, ConnectionRefusedError):
        if a.socket:
            raise
else:
    p.error('No running UI found; start bash emulation/launch_features.sh')
stream = s.makefile('rb')
json.loads(stream.readline())
serial = 0

def command(name, arguments=None):
    global serial
    serial += 1
    msg = {'execute': name, 'id': serial}
    if arguments is not None:
        msg['arguments'] = arguments
    s.sendall((json.dumps(msg) + '\n').encode())
    while True:
        line = stream.readline()
        if not line:
            raise RuntimeError('QMP disconnected')
        reply = json.loads(line)
        if reply.get('id') != serial:
            continue
        if 'error' in reply:
            raise RuntimeError(reply['error'])
        return reply.get('return')

command('qmp_capabilities')
fixtures = []
if a.vehicle_network:
    fixtures.append('1d:' + {'healthy':'68','economy':'78','unknown':'60'}[a.vehicle_network])
if a.temperature is not None or a.temperature_unknown:
    raw = 255 if a.temperature_unknown else int((a.temperature + 40) * 2)
    command('qom-set', {'path': '/machine', 'property': 'bench-temperature-raw', 'value': raw})
    print(json.dumps({'simulated_temperature_c': a.temperature, 'raw': raw, 'physical_sensor': False}))
if a.clock_live:
    command('qom-set', {'path': '/machine', 'property': 'bench-clock-live', 'value': True})
if a.stationary:
    fixtures.append('15:0000000000000080')
if a.functions_available:
    fixtures.append('0f:00040000000000')
if a.eco:
    fixtures.append('1a:000000' + ('80' if a.eco == 'off' else '40') + '00')
if a.parking:
    # The native visual-request bit is D5bit1. Clear it when no overlay is
    # requested; otherwise a periodic "off" fixture can keep reopening it.
    fixtures.append('05:' + {'active': '90', 'standby': 'b4', 'off': '48'}[a.parking]
                    + 'b015fcfc' + ('ae' if a.parking == 'active' else 'ac') + 'c200')
if a.traction:
    mode = ['off', 'normal', 'snow', 'mud', 'sand'].index(a.traction)
    fixtures.append(f'0c:00000000{mode << 1:02x}00')
for fixture in fixtures:
    command('qom-set', {'path': '/machine', 'property': 'bench-can', 'value': fixture})
    print(json.dumps({'simulated_vehicle_input': fixture, 'physical_can': False}))
if a.notify:
    if not a.eco:
        p.error('--notify requires --eco')
    command('qom-set', {'path': '/machine', 'property': 'bench-alert',
                        'value': 'eco-' + a.eco})
if a.esp:
    command('qom-set', {'path': '/machine', 'property': 'bench-esp-enabled',
                        'value': a.esp == 'on'})
    print(json.dumps({'simulated_esp_enabled': a.esp == 'on', 'physical_can': False}))
if a.panel:
    keys = {'menu': (0, 2), 'src': (0x3e, 1), 'cheat': (0x15, 4),
            'versions': (0x17, 4),
            'media': (0x15, 2), 'nav': (0x16, 2), 'config': (0x17, 2),
            'drive': (0x1a, 2), 'web': (0x1b, 1), 'telephone': (0x14, 1),
            'climate': (0x18, 1)}
    current = command('qom-get', {'path': '/machine', 'property': 'frontpanel-key-variant'})
    destinations = {'media':100, 'config':250, 'web':400, 'telephone':550, 'drive':700}
    if a.car_fmux and (a.panel == 'menu' or a.panel in destinations):
        # The live car's FMUX configuration maps function841 to key01 in
        # profileA1 and key00 in profile00. A1/key00 is function1091, which
        # opens the current application's secondary menu. Do not switch the
        # virtual panel identity between presses or alter the stored FMUX blob.
        key, status = (1 if current == 0xa1 else 0), 2
    else:
        if not a.car_fmux:
            variant = 0xa1 if a.panel == 'menu' else 0
            if current != variant:
                command('qom-set', {'path':'/machine', 'property':'frontpanel-key-variant', 'value':variant})
                time.sleep(.35)
        key, status = keys[a.panel]
    if status == 2:
        # Repeated release-only messages can retain the native keyboard's
        # previous state. Model a real press before each short release.
        command('qom-set', {'path': '/machine', 'property': 'frontpanel-event',
                            'value': (key << 8) | 1})
        time.sleep(.15)
    command('qom-set', {'path': '/machine', 'property': 'frontpanel-event',
                        'value': (key << 8) | status})
    if a.car_fmux and a.panel in destinations:
        # Use genuine native selector tiles because the real FMUX blob has
        # the legacy direct Web/telephone keys disabled. No guest call or
        # database/configuration write is needed for navigation.
        time.sleep(1)
        command('input-send-event', {'events':[
            {'type':'abs','data':{'axis':'x','value':round(destinations[a.panel]*32767/799)}},
            {'type':'abs','data':{'axis':'y','value':round(215*32767/479)}},
            {'type':'btn','data':{'button':'left','down':True}}]})
        time.sleep(.18)
        command('input-send-event', {'events':[
            {'type':'btn','data':{'button':'left','down':False}}]})
if a.key:
    key, status = a.key
    command('qom-set', {'path': '/machine', 'property': 'frontpanel-event',
                        'value': (key << 8) | status})
if a.click:
    x, y = a.click
    if not (0 <= x < 800 and 0 <= y < 480):
        p.error('click must be inside the 800x480 touchscreen')
    command('input-send-event', {'events': [
        {'type': 'abs', 'data': {'axis': 'x', 'value': round(x * 32767 / 799)}},
        {'type': 'abs', 'data': {'axis': 'y', 'value': round(y * 32767 / 479)}},
        {'type': 'btn', 'data': {'down': True, 'button': 'left'}},
    ]})
    time.sleep(.25)
    command('input-send-event', {'events': [
        {'type': 'btn', 'data': {'down': False, 'button': 'left'}},
    ]})
if a.screenshot:
    if a.panel or a.key or a.click or fixtures or a.esp or a.clock_live or a.temperature is not None or a.temperature_unknown:
        time.sleep(max(0, a.settle))
    command('screendump', {'filename': str(a.screenshot.resolve()),
                           'format': 'png' if a.screenshot.suffix.lower() == '.png' else 'ppm'})
if a.info_mice:
    print(json.dumps(command('query-mice'), indent=2))
if a.status:
    print(json.dumps(command('query-status'), indent=2))
if a.usb_status:
    for address in (0x80001100, 0x80001108):
        print(command('human-monitor-command', {
            'command-line': f'xp /1wx {address:#x}'
        }).strip())
if a.touch_calibration or a.touch_state:
    raw = command('human-monitor-command', {'command-line': 'xp /1wx 0x036777dc'})
    print(raw.strip())
    match = re.search(r':\s*0x([0-9a-fA-F]+)', raw)
    if match:
        address = int(match.group(1), 16)
        if 0 < address < 0x1ffffc00:
            for offset in (0x3be, 0x3c0):
                print(command('human-monitor-command', {
                    'command-line': f'xp /1hx {address + offset:#x}'
                }).strip())
            if a.touch_state:
                for offset in (0x51c, 0x52c, 0x53c, 0x59c, 0xac, 0xb0, 0x80):
                    print(command('human-monitor-command', {
                        'command-line': f'xp /4wx {address + offset:#x}'
                    }).strip())
if a.quit:
    command('quit')
stream.close()
s.close()
