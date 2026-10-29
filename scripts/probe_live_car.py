#!/usr/bin/env python3
"""Read-only host inventory and Telnet greeting probe for the paired Peugeot.

Does not mount devices, send shell commands, change Bluetooth connections,
modify a vehicle file, or substitute update-package defaults for live data.
Only probes neighbors on this device's active BlueZ PAN interface.
"""
import argparse
import datetime
import ipaddress
import json
import re
import socket
import subprocess
from pathlib import Path

from local_device_config import load_local_device_config


def run(argv):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=12)
        return {"argv": argv, "returncode": p.returncode,
                "stdout": p.stdout, "stderr": p.stderr}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"argv": argv, "error": str(exc)}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    local = load_local_device_config()
    ap.add_argument('--address', default=local.get('bluetooth_address'),
                    help='Bluetooth peer; alternatively set SMEG_BLUETOOTH_ADDRESS or local JSON')
    ap.add_argument('--output', type=Path,
                    default=Path('artifacts/live_car_backup/connection-probe.json'))
    a = ap.parse_args()
    if not a.address:
        ap.error('Provide --address, SMEG_BLUETOOTH_ADDRESS or local bluetooth_address')
    if not re.fullmatch(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', a.address):
        ap.error('invalid Bluetooth address')
    r = {'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
         'device': a.address, 'vehicle_files_written': False,
         'live_database_files_extracted': [], 'telnet': [],
         'scope': 'connection diagnostics only; no database modification/injection'}
    r['inventory'] = [run(cmd) for cmd in (
        ['lsusb'], ['lsusb', '-t'],
        ['lsblk', '-J', '-o', 'NAME,TYPE,SIZE,FSTYPE,LABEL,MOUNTPOINTS,RO,TRAN'],
        ['ip', '-j', 'address'], ['ip', '-j', 'route'], ['ip', '-j', 'neigh'],
        ['bluetoothctl', 'info', a.address])]
    try:
        import dbus
        bus = dbus.SystemBus()
        path = '/org/bluez/hci0/dev_' + a.address.upper().replace(':', '_')
        obj = bus.get_object('org.bluez', path)
        props = dbus.Interface(obj, 'org.freedesktop.DBus.Properties')
        device = props.GetAll('org.bluez.Device1', timeout=5)
        network = props.GetAll('org.bluez.Network1', timeout=5)
        r['bluetooth_connected'] = bool(device.get('Connected', False))
        r['pan_connected'] = bool(network.get('Connected', False))
        iface = str(network.get('Interface', ''))
        r['pan_interface'] = iface
        if r['pan_connected'] and iface:
            peers = run(['ip', '-j', 'neigh', 'show', 'dev', iface])
            if peers.get('returncode') != 0:
                raise RuntimeError('cannot inspect PAN neighbors')
            for peer in json.loads(peers['stdout']):
                ip = peer.get('dst', '')
                if ipaddress.ip_address(ip).version != 4:
                    continue
                if set(peer.get('state', [])) & {'FAILED', 'INCOMPLETE'}:
                    continue
                entry = {'ip': ip, 'port': 23, 'interface': iface}
                try:
                    with socket.create_connection((ip, 23), timeout=3) as s:
                        entry['connected'] = True
                        # Receive only: no Telnet login or guest shell command.
                        s.settimeout(1)
                        try:
                            entry['greeting_hex'] = s.recv(4096).hex()
                        except socket.timeout:
                            entry['greeting_hex'] = ''
                except OSError as exc:
                    entry.update(connected=False, error=str(exc))
                r['telnet'].append(entry)
        r['status'] = ('telnet_reachable_extraction_not_performed'
                       if any(x.get('connected') for x in r['telnet'])
                       else 'blocked_no_reachable_car_telnet')
    except Exception as exc:
        r.update(status='blocked_connection_probe_failed', error=str(exc))
    r['phase2'] = 'not_started_requires_verified_live_backup'
    r['phase3'] = 'not_started_requires_modified_live_databases'
    r['mirrorlink_test_screenshot'] = None
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(r, indent=2) + '\n')
    print(json.dumps({k: v for k, v in r.items() if k != 'inventory'}, indent=2))
    return 0 if any(x.get('connected') for x in r['telnet']) else 2


if __name__ == '__main__':
    raise SystemExit(main())
