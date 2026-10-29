#!/usr/bin/env python3
"""Build content-only diagnostic media for the isolated INT_E browser test.

No maintenance module, network request, firmware payload, or vehicle API.
Only new regular images under this workspace's phase11 artifacts are accepted.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'artifacts/phase11/usb-capabilities'
HTML = b'''<!DOCTYPE html><html><head><meta charset="utf-8">
<title>USB browser capability probe</title><style>
body{margin:0;background:#102337;color:white;font:24px Arial}
main{margin:65px 105px}button{font:26px Arial;padding:20px}
#features{font:14px monospace;line-height:16px}#asset{position:absolute;right:10px;top:80px;width:95px;height:45px}
</style></head><body><main><h1>USB page loaded</h1>
<p id="state">JavaScript not run</p>
<button onclick="n++;document.getElementById('state').innerHTML='Touch acknowledged: '+n">Test native touch</button>
<p>Diagnostic only. No vehicle controls.</p><div id="features"></div></main>
<script>
var n=0, results={JSON:'WAIT',FileJSON:'WAIT',ExternalJS:'WAIT',SVG:'WAIT',Canvas:'WAIT',Storage:'WAIT',NativeClock:'WAIT',CarTrip:'WAIT'};
var expectedJSON='{"marker":"SMEG_USB_RESOURCE_PROBE"}'+String.fromCharCode(10);
var nativeJSONParser=typeof JSON==='object'&&typeof JSON.parse==='function'?'yes':'no';
function show(){var s='',k;for(k in results){s+=k+': '+results[k]+'<br>';}document.getElementById('features').innerHTML=s;}
document.getElementById('state').innerHTML='JavaScript running from USB';
function testCanvas(){try{var c=document.createElement('canvas');c.width=2;c.height=2;
var ctx=c.getContext('2d');ctx.fillStyle='rgb(42,43,44)';ctx.fillRect(0,0,2,2);
results.Canvas=ctx.getImageData(0,0,1,1).data[0]===42?'PASS':'FAIL';}catch(e){results.Canvas='UNAVAILABLE';}show();}
function testStorage(){try{var old=localStorage.getItem('smeg_usb_capability_probe');
localStorage.setItem('smeg_usb_capability_probe','test');
results.Storage=localStorage.getItem('smeg_usb_capability_probe')==='test'?'PASS':'FAIL';
if(old===null)localStorage.removeItem('smeg_usb_capability_probe');else localStorage.setItem('smeg_usb_capability_probe',old);
}catch(e){results.Storage='UNAVAILABLE';}show();}
try{var xhr=new XMLHttpRequest();xhr.onreadystatechange=function(){if(xhr.readyState===4){
try{results.JSON=xhr.responseText===expectedJSON?'PASS raw; native parser '+nativeJSONParser:'FAIL content';}
catch(e){results.JSON='FAIL status '+xhr.status+' len '+xhr.responseText.length;}show();}};
xhr.open('GET','probe.json',true);xhr.send(null);}catch(e){results.JSON='UNAVAILABLE';}
try{var fx=new XMLHttpRequest();fx.onreadystatechange=function(){if(fx.readyState===4){
try{results.FileJSON=fx.responseText===expectedJSON?'PASS raw':'FAIL content';}
catch(e){results.FileJSON='FAIL status '+fx.status+' len '+fx.responseText.length;}show();}};
fx.open('GET','file:///bd0/SMEG_CAP/probe.json',true);fx.send(null);}catch(e){results.FileJSON='UNAVAILABLE';}
function testSVG(){var im=new Image();im.id='asset';im.onload=function(){results.SVG='PASS';show();};
im.onerror=function(){results.SVG='FAIL';show();};im.src='asset.svg';document.body.appendChild(im);show();
}
function testClock(){try{results.NativeClock=GetCarTime.Hours()+':'+GetCarTime.Minutes();}
catch(e){results.NativeClock='UNAVAILABLE';}show();}
function testTrip(){try{results.CarTrip='speed '+GetCar.Speed()+' range '+GetCar.Autonomy()+' trip '+GetCarTrip1.Mileage();}
catch(e){results.CarTrip='UNAVAILABLE';}show();}
setTimeout(function(){results.SVG='RUNNING';show();setTimeout(testSVG,200);},3000);
setTimeout(function(){results.NativeClock='RUNNING';show();setTimeout(testClock,200);},6000);
setTimeout(function(){results.Canvas='RUNNING';show();setTimeout(testCanvas,200);},10000);
setTimeout(function(){results.Storage='RUNNING';show();setTimeout(testStorage,200);},14000);
setTimeout(function(){results.CarTrip='RUNNING';show();setTimeout(testTrip,200);},16000);
show();
</script><script src="probe.js"></script></body></html>'''
FILES = {
    'index.html': HTML,
    'probe.json': b'{"marker":"SMEG_USB_RESOURCE_PROBE"}\n',
    'probe.js': b'results.ExternalJS="PASS";show();\n',
    'asset.svg': b'<svg xmlns="http://www.w3.org/2000/svg" width="95" height="45"><rect width="95" height="45" fill="#42ad73"/><text x="10" y="29" font-size="20" fill="white">USB SVG</text></svg>',
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--template', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    a = parser.parse_args()
    template, output = a.template.resolve(), a.output.resolve()
    if not template.is_file() or not template.is_relative_to(BASE):
        parser.error('Regular phase11 template required')
    if output.exists() or not output.is_relative_to(BASE):
        parser.error('New phase11 image required')
    env = dict(os.environ, MTOOLS_SKIP_CHECK='1')
    def run(*args, check=True):
        return subprocess.run(args, check=check, capture_output=True, env=env)
    if run('mdir', '-i', str(template)+'@@1048576', '::/FLYING', check=False).returncode == 0:
        parser.error('Template must contain no FLYING maintenance directory')
    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(template, output)
    spec = str(output)+'@@1048576'
    with tempfile.TemporaryDirectory(prefix='smeg-usb-content-') as directory:
        for name, data in FILES.items():
            p = Path(directory)/name
            p.write_bytes(data)
            run('mcopy', '-o', '-i', spec, str(p), '::/SMEG_CAP/'+name)
            assert run('mtype', '-i', spec, '::/SMEG_CAP/'+name).stdout == data
    report = {'emulator_only': True, 'physical_device_access': False,
              'maintenance_module': False, 'network_access': False,
              'files': [{'path': 'SMEG_CAP/'+n, 'sha256': hashlib.sha256(d).hexdigest()}
                        for n, d in FILES.items()]}
    output.with_suffix('.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'image': str(output), 'content_only': True}))


if __name__ == '__main__':
    main()
