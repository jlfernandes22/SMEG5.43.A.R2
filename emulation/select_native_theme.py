#!/usr/bin/env python3
"""Drive the native Audio theme menu through QMP input only; no guest writes.

Screenshots and native persistent state require independent verification.
"""
import argparse
import json
from pathlib import Path
import time
import re
import subprocess
from run_usb_probe import QMP

ROOT = Path(__file__).resolve().parents[1]
ORDER = ['GRAPHIC','ELLIPTIC','CUBIC','REFLEX','ESSENTIEL','REDLINE','SQUARE','WARMLIGHT']
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--prefix', required=True)
p.add_argument('--theme', choices=ORDER, required=True)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--confirm', action='store_true')
p.add_argument('--prepare-only', action='store_true', help='Open/capture chooser without selecting or confirming')
p.add_argument('--chooser-open', action='store_true', help='Chooser is already open; do not navigate settings')
p.add_argument('--auto-visible', action='store_true', help='Choose only an exact theme label recognized locally from the current chooser screenshot')
p.add_argument('--visible-row', type=int, choices=range(1,6), help='Explicit 1-based visible row, verified from chooser screenshot')
p.add_argument('--scroll-up', type=int, default=0)
p.add_argument('--scroll-down', type=int, default=0)
p.add_argument('--settings-open', action='store_true')
p.add_argument('--color-at', nargs=2, type=int, default=[675,235], metavar=('X','Y'))
a = p.parse_args()
if not a.prepare_only and a.visible_row is None and not a.auto_visible:
    p.error('Inspect --prepare-only screenshot, then pass --chooser-open --visible-row; scrolling is not a reliable absolute index')
if a.prepare_only and a.confirm:
    p.error('--prepare-only cannot confirm')
if not 0 <= a.scroll_up <= 12 or not 0 <= a.scroll_down <= 12:
    p.error('Scroll count must be0..12')
out = a.output.resolve()
assert out.is_relative_to(ROOT/'artifacts/phase15') and not out.exists()
out.mkdir(parents=True)
q = QMP(a.prefix+'.qmp')
events = []
observations = []
confirm_sent = False


def tap(x,y):
    q.call('input-send-event',{'events':[
        {'type':'abs','data':{'axis':'x','value':round(x*32767/799)}},
        {'type':'abs','data':{'axis':'y','value':round(y*32767/479)}},
        {'type':'btn','data':{'button':'left','down':True}}]})
    time.sleep(.2)
    q.call('input-send-event',{'events':[{'type':'btn','data':{'button':'left','down':False}}]})
    events.append({'touch':[x,y],'time_monotonic':time.monotonic()})


def capture(name):
    q.call('screendump',{'filename':str(out/(name+'.png')),'format':'png'})


def recognize_rows(path):
    from PIL import Image
    image = Image.open(path)
    tessdata = ROOT/'artifacts/phase15/ocr'
    if not (tessdata/'eng.traineddata').is_file():
        raise RuntimeError('Missing local OCR data; use inspected --visible-row instead')
    labels = []
    for row,y in enumerate([95,153,210,270,326],1):
        crop = out/f'ocr-row-{row}.png'
        image.crop((65,y-25,490,y+25)).resize((850,100)).save(crop)
        result = subprocess.run(['tesseract',str(crop),'stdout','--tessdata-dir',str(tessdata),
                                 '--psm','7','-c','tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ'],
                                capture_output=True,text=True,check=True)
        labels.append(re.sub('[^A-Z]','',result.stdout))
    observations.append({'screenshot':str(path),'visible_labels':labels})
    return labels


try:
    if not a.settings_open and not a.chooser_open:
        variant = q.call('qom-get',{'path':'/machine','property':'frontpanel-key-variant'})
        key = 1 if variant == 0xa1 else 0
        for state in (1,2):
            q.call('qom-set',{'path':'/machine','property':'frontpanel-event','value':key<<8|state})
            time.sleep(.15)
        time.sleep(.75);tap(250,215);time.sleep(3)
    if not a.chooser_open:
        capture('settings')
        tap(*a.color_at);time.sleep(3)
    capture('list-initial')
    # Arrow movement is relative, not a reliable reset-to-top operation.
    # The caller must inspect the list and explicitly identify a visible row.
    for _ in range(a.scroll_up):tap(30,90);time.sleep(1.2)
    for _ in range(a.scroll_down):tap(30,330);time.sleep(1.2)
    capture('list-target-range')
    row = a.visible_row
    if a.auto_visible and not a.prepare_only:
        for attempt in range(13):
            name = f'list-ocr-step-{attempt}'
            capture(name)
            labels = recognize_rows(out/(name+'.png'))
            if a.theme in labels:
                row = labels.index(a.theme)+1
                break
            known = [ORDER.index(t) for t in labels if t in ORDER]
            if not known:
                raise RuntimeError('No exact known chooser labels; refusing blind selection')
            if attempt == 12:
                raise RuntimeError('Requested label not visible after bounded relative scrolling')
            tap(30,90 if ORDER.index(a.theme)<min(known) else 330)
            time.sleep(1.2)
    if not a.prepare_only:
        tap(225,[95,153,210,270,326][row-1])
        time.sleep(3);capture('selected-preview')
        if a.confirm:
            tap(58,421);confirm_sent=True;time.sleep(3);capture('confirmation')

finally:
    q.close()
    (out/'input.json').write_text(json.dumps({'requested_theme':a.theme,'actual_theme_verified':False,'confirm_input_sent':confirm_sent,'OCR_observations':observations,
        'prepare_only':a.prepare_only,'visible_row':a.visible_row,'scroll_up':a.scroll_up,'scroll_down':a.scroll_down,
        'QMP_input_only':True,'guest_RAM_patches':False,'events':events},indent=2)+'\n')
print(out,flush=True)
