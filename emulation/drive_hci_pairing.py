#!/usr/bin/env python3
"""Select only the real, resolved OnePlus target in an isolated native UI."""
import json
import argparse
from pathlib import Path
import subprocess
import time
from PIL import Image, ImageOps

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--submit-test-pin',action='store_true',help='Submit announced test PIN1234 in the native guest; phone confirmation stays manual')
args=parser.parse_args()

case = Path('artifacts/phase4/runs/hci_compat')
base = ['python3', 'emulation/ui_control.py', '--socket', str(case/'control.qmp')]
output = Path('artifacts/phase4/hci-pairing-action.json')
screen = Path('artifacts/phase4/hci-pairing-automatic.png')
report = {'physical_car_access': False, 'target': '22:22:4D:F1:4E:5E',
          'real_phone_name_received': False, 'native_target_selected': False}

def rows():
    data = [json.loads(line) for line in (case/'hci.jsonl').read_text().splitlines()]
    start = max(i for i, row in enumerate(data) if row['event'] == 'listening')
    return data[start:]

def control(*args):
    subprocess.run(base + list(args), check=True, timeout=10)

try:
    deadline = time.monotonic() + 150
    while time.monotonic() < deadline:
        if (case/'hci.sock').exists() and (case/'control.qmp').exists():
            if any(r.get('direction') == 'guest' and r.get('hex') == '011a0c0103' for r in rows()):
                break
        time.sleep(.2)
    else:
        raise TimeoutError('Native radio setup not ready')
    control('--panel', 'telephone', '--screenshot', str(screen))
    scan_started = time.monotonic()
    control('--click', '598', '231', '--settle', '1')
    print('Native discovery started', flush=True)
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        for row in rows():
            if row['monotonic'] < scan_started or row.get('direction') != 'radio' or not row.get('hex', '').startswith('0407'):
                continue
            packet = bytes.fromhex(row['hex'])
            if packet[3:10] == bytes.fromhex('005e4ef14d2222'):
                name = packet[10:].split(b'\0', 1)[0].decode('utf-8', 'replace')
                if name == 'OnePlus 12':
                    report['real_phone_name_received'] = True
        if report['real_phone_name_received']:
            break
        time.sleep(.2)
    else:
        raise TimeoutError('No real OnePlus name response')
    deadline = time.monotonic() + 8
    roi = screen.with_name('hci-pairing-ocr.png')
    while time.monotonic() < deadline:
        control('--screenshot', str(screen))
        image = Image.open(screen).crop((200, 135, 740, 193)).resize((1080, 116)).convert('L')
        ImageOps.invert(image.point(lambda v: 255 if v > 200 else 0)).save(roi)
        ocr = subprocess.run(['tesseract', str(roi), 'stdout', '-l', 'afr', '--psm', '7'],
                             capture_output=True, text=True, check=True, timeout=4).stdout
        if ''.join(ocr.split()).casefold() == 'oneplus12':
            selection_started = time.monotonic()
            control('--click', '320', '165', '--settle', '1', '--screenshot', str(screen))
            report['native_target_selected'] = True
            break
        time.sleep(.2)
    if report['native_target_selected']:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            requested = any(r['monotonic'] >= selection_started and r.get('direction') == 'radio'
                            and r.get('hex') == '0416065e4ef14d2222' for r in rows())
            if requested:
                control('--screenshot', str(screen))
                image = Image.open(screen).crop((250, 55, 635, 110)).resize((770, 110)).convert('L')
                ImageOps.invert(image.point(lambda v: 255 if v > 160 else 0)).save(roi)
                header = subprocess.run(['tesseract', str(roi), 'stdout', '-l', 'afr', '--psm', '7'],
                                        capture_output=True, text=True, check=True, timeout=4).stdout
                if 'BLUETOOTHCODE' in ''.join(header.split()).upper():
                    for x, y in [(239,192),(398,192),(559,192),(239,250)]:
                        control('--click', str(x), str(y))
                        time.sleep(.5)
                    control('--screenshot', str(screen))
                    report['test_PIN_entered_not_submitted'] = '1234'
                    if args.submit_test_pin:
                        control('--click','400','422','--settle','1','--screenshot',str(screen))
                        report.pop('test_PIN_entered_not_submitted')
                        report['test_PIN_submitted']='1234'
                        print('Native test PIN1234 submitted; confirm on the phone if requested',flush=True)
                    break
            time.sleep(.2)
    report['screenshot'] = str(screen)
    print(json.dumps(report), flush=True)
except Exception as exc:
    report['error'] = str(exc)
    raise
finally:
    output.write_text(json.dumps(report, indent=2) + '\n')
