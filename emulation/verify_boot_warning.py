#!/usr/bin/env python3
"""Observe an untouched QEMU boot, OCR screenshots and retain warning evidence."""
import argparse,hashlib,json,socket,subprocess,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,default=Path('artifacts/phase4/runs/features'));p.add_argument('--output',type=Path,default=Path('artifacts/phase4/network-health-boot-check'));p.add_argument('--seconds',type=float,default=55);p.add_argument('--ocr-language');a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
languages=subprocess.run(['tesseract','--list-langs'],capture_output=True,text=True,check=True).stdout.splitlines()[1:]
language=a.ocr_language or next((v for v in ('eng','afr') if v in languages),None)
if language not in languages:p.error('Install OCR language data or select an available --ocr-language')
positive=Path('artifacts/phase4/network-health-unknown-early.png')
positive_verified=False
if positive.exists():
 r=subprocess.run(['tesseract',str(positive),'stdout','-l',language,'--psm','11'],capture_output=True,text=True,timeout=6,check=True)
 positive_verified='internal vehicle problem' in r.stdout.lower()
 if not positive_verified:p.error('OCR failed to recognize the saved positive warning control')
s=socket.socket(socket.AF_UNIX);s.settimeout(5);s.connect(str(a.directory/'control.qmp'));f=s.makefile('rb');f.readline();seq=0
def qmp(name,args=None):
 global seq
 seq+=1;m={'execute':name,'id':seq}
 if args is not None:m['arguments']=args
 s.sendall((json.dumps(m)+'\n').encode())
 while True:
  r=json.loads(f.readline())
  if r.get('id')==seq:
   if 'error' in r:raise RuntimeError(r['error'])
   return r['return']
qmp('qmp_capabilities');qmp('system_reset');start=time.monotonic();results=[]
while time.monotonic()-start<a.seconds:
 elapsed=time.monotonic()-start;image=a.output/f'boot-{len(results):03}.png'
 qmp('screendump',{'filename':str(image.resolve()),'format':'png'})
 r=subprocess.run(['tesseract',str(image),'stdout','-l',language,'--psm','11'],capture_output=True,text=True,timeout=6,check=True)
 text=r.stdout;warning='internal vehicle problem' in text.lower() or 'device cannot operate' in text.lower()
 results.append({'elapsed_s':round(elapsed,2),'image':str(image),'ocr':text,'warning':warning,'sha256':hashlib.sha256(image.read_bytes()).hexdigest()})
 time.sleep(.65)
report={'scope':'Cold reset, no clicks, no suppression, no physical car access','duration_s':time.monotonic()-start,'ocr_language':language,'positive_warning_control_detected':positive_verified,'frames':results,'warning_frames':[r['image']for r in results if r['warning']],'final_status':qmp('query-status')}
(a.output/'verification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'frames':len(results),'warning_frames':report['warning_frames'],'final_status':report['final_status']}))
