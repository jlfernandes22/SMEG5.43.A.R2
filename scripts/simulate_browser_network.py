#!/usr/bin/env python3
"""Bounded, emulator-only browser/network diagnostic; never asserts PAN/DUN.

Uses only private copies of the two approved persistent NAND snapshots. No
physical USB, HCI radio or NIC backend. Baseline has no guest helper/RAM
write; explicit helper/profile options are labelled diagnostic simulation.
No instruction patches or persistent parameter setters are used.
A host loopback HTTP witness is a host-only positive control, NOT guest HTTP.
"""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import re
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'emulation'))
from run_usb_probe import QMP, RSP
SOURCES = [ROOT/'artifacts/phase13/disk-control-nativeFULL35/nand.raw',
           ROOT/'artifacts/phase8/usb-maintenance/runs/nativeERASED33/nand.raw']
OUTROOT = ROOT/'artifacts/phase14/browser-network'
POINTS = {0x4c86c38:'isInternetProfileReady', 0x4c86cec:'isFullWebAvailable',
          0x4c8fd54:'internet_openPanel',0x4cb074c:'shLoadUrl',
          0x4d58560:'GUIInternetClient_ProcessConfigMessage',
          0x20383dc:'InetAddonConnector_ProcessConfigMessage',
          0x20376f8:'InetAddonConnector_process_command',
          0x205b8bc:'load_URL_QtSignal',0x26f3c18:'GetLoadURLData',
          0x4d1e938:'BrowserWrapper_loadUrl',0x4d1efe8:'QWebView_load'}


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        while chunk := f.read(4*1024*1024): h.update(chunk)
    return h.hexdigest()


def build_guest_loopback(out, simulate_profile=False):
    """Build only; execution requires an explicitly diagnostic virtual-USB run."""
    kernel=ROOT/'artifacts/phase2/package/SMEG_PLUS_UPG/BSP/SMEG_PLUS_256/vxWorks.bin'
    blob=kernel.read_bytes()
    addresses={'socket':0x457618,'bind':0x4576dc,'listen':0x45776c,'accept':0x4577ec,
               'connect':0x4578d0,'send':0x457a8c,'recv':0x457c68,'close':0x48fe40,'taskSpawn':0x58867c,
               'taskDelay':0x589a2c,'sysClkRateGet':0x218aec,'fopen':0x2c7c70,'fprintf':0x2ca3a0,'fflush':0x2c78d0,'fclose':0x2c7618}
    guards=[]
    for name,addr in addresses.items():
        raw=blob[addr-0x200000:addr-0x200000+32];h=2166136261
        for b in raw:h=((h^b)*16777619)&0xffffffff
        guards.append({'name':name,'address':addr,'length':32,'fnv1a32':h,'bytes':raw.hex()})
    raw=(ROOT/'artifacts/phase2/applications/AUDIO_BT_256/app_segment2.bin').read_bytes()[0xb074c:0xb074c+32]
    h=2166136261
    for b in raw:h=((h^b)*16777619)&0xffffffff
    guards.append({'name':'shLoadUrl','address':0x4cb074c,'length':32,'fnv1a32':h,'bytes':raw.hex()})
    if simulate_profile:
        for name,addr in [('WWWInstance',0x4c9b564),('isInternetProfileReady',0x4c86c38)]:
            raw=(ROOT/'artifacts/phase2/applications/AUDIO_BT_256/app_segment2.bin').read_bytes()[addr-0x4c00000:addr-0x4c00000+32];h=2166136261
            for b in raw:h=((h^b)*16777619)&0xffffffff
            guards.append({'name':name,'address':addr,'length':32,'fnv1a32':h,'bytes':raw.hex()})
    table=',\n'.join('{0x%xu,%du,0x%xu}'%(x['address'],x['length'],x['fnv1a32']) for x in guards)
    code=r"""/* DIAGNOSTIC SIMULATION ONLY. Not a firmware package or PAN/DUN.
 * Only127.0.0.1 TCP18080; log only on emulatedUSB /bd0/PHASE14.
 * Exact BSP256 API fingerprints checked before any invocation. */
 typedef unsigned int u32;typedef void FILE;
 void *memcpy(void *d,const void *s,unsigned n){unsigned char*x=d;const unsigned char*y=s;unsigned i;for(i=0;i<n;i++)x[i]=y[i];return d;}
 static int worker(void);static int url_worker(void);static FILE*shared_log;static volatile int browser_request_seen;
 static const struct {u32 address,length,hash;} checks[]={@TABLE@};
 static u32 hash(u32 address,u32 n){const unsigned char*p=(void*)address;u32 h=2166136261u;while(n--)h=(h^*p++)*16777619u;return h;}
 /* Entry explicitly placed first in .text via section ordering at link. */
 __attribute__((section(".text.entry"))) int phase14_loopback_entry(void){
 unsigned i;for(i=0;i<sizeof(checks)/sizeof(checks[0]);i++)if(hash(checks[i].address,checks[i].length)!=checks[i].hash)return -90;
 return ((int(*)(char*,int,int,int,int(*)(void),int,int,int,int,int,int,int,int,int,int))0x58867c)("p14LoopbackHTTP",130,0,32768,worker,0,0,0,0,0,0,0,0,0,0);}
 static int worker(void){
 FILE*log=((FILE*(*)(const char*,const char*))0x2c7c70)("/bd0/PHASE14/loopback.log","wb");
 int fd,client,rc,n,i;unsigned char addr[16];char req[1024];
 const char body[]="<!doctype html><html><head><title>PHASE14 GUEST LOOPBACK</title></head><body style='background:#14763b;color:white;font-size:32px'><h1>GUEST HTTP SUCCESS</h1><p>Native VxWorks TCP loopback. Not PAN or DUN.</p><p>CANARY P14-HTTP-18080</p></body></html>";
 const char header[]="HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n";
 if(!log)return -1;((int(*)(FILE*))0x2c7618)(log);shared_log=0;
 #define LOG(...) do{FILE*stream=((FILE*(*)(const char*,const char*))0x2c7c70)("/bd0/PHASE14/loopback.log","ab");if(stream){((int(*)(FILE*,const char*,...))0x2ca3a0)(stream,__VA_ARGS__);((int(*)(FILE*))0x2c7618)(stream);}}while(0)
 for(i=0;i<16;i++)addr[i]=0;addr[0]=16;addr[1]=2;addr[2]=0x46;addr[3]=0xa0;addr[4]=127;addr[7]=1;
 fd=((int(*)(int,int,int))0x457618)(2,1,0);LOG("SOCKET=%d scope=guest-loopback-only\n",fd);if(fd<0)goto done;
 rc=((int(*)(int,void*,int))0x4576dc)(fd,addr,16);LOG("BIND127.0.0.1:18080=%d\n",rc);if(rc<0)goto closefd;
 rc=((int(*)(int,int))0x45776c)(fd,2);LOG("LISTEN=%d\n",rc);if(rc<0)goto closefd;
 @PROFILE@
 rc=((int(*)(char*,int,int,int,int(*)(void),int,int,int,int,int,int,int,int,int,int))0x58867c)("p14URLDiagnostic",135,0,32768,url_worker,0,0,0,0,0,0,0,0,0,0);LOG("URL_TASK=%08x\n",rc);
 for(i=0;i<2;i++){
 client=((int(*)(int,void*,void*))0x4577ec)(fd,0,0);LOG("ACCEPT=%d\n",client);if(client<0)break;
 n=((int(*)(int,void*,int,int))0x457c68)(client,req,1023,0);if(n>0)req[n]=0;else req[0]=0;LOG("RECV=%d REQUEST=%s\n",n,req);
 if(n>0&&n>16&&req[4]=='/'&&req[5]=='p')browser_request_seen=1;
 if(n>0){int off=0,w;while(off<(int)sizeof(header)-1){w=((int(*)(int,const void*,int,int))0x457a8c)(client,header+off,sizeof(header)-1-off,0);if(w<=0)break;off+=w;}LOG("HEADER_SENT=%d\n",off);
 off=0;while(off<(int)sizeof(body)-1){w=((int(*)(int,const void*,int,int))0x457a8c)(client,body+off,sizeof(body)-1-off,0);if(w<=0)break;off+=w;}LOG("BODY_SENT=%d EXPECTED=%d\n",off,(int)sizeof(body)-1);}
 ((int(*)(int))0x48fe40)(client);
 }
 closefd:((int(*)(int))0x48fe40)(fd);
 done:return 0;}
 static int url_worker(void){FILE*log=shared_log;int fd,n,total=0;unsigned char addr[16];char response[1024];int i,ok=0;const char request[]="GET /selfcheck.html HTTP/1.0\r\nHost: 127.0.0.1\r\nUser-Agent: P14NativeSelfCheck\r\n\r\n";int rate=((int(*)(void))0x218aec)();u32 thread;
 LOG("URL_WORKER_ENTER_RATE=%d\n",rate);if(rate<1||rate>10000)return -1;((int(*)(int))0x589a2c)(rate*5);
 for(i=0;i<16;i++)addr[i]=0;addr[0]=16;addr[1]=2;addr[2]=0x46;addr[3]=0xa0;addr[4]=127;addr[7]=1;
 fd=((int(*)(int,int,int))0x457618)(2,1,0);LOG("SELF_SOCKET=%d\n",fd);
 if(fd>=0){n=((int(*)(int,void*,int))0x4578d0)(fd,addr,16);LOG("SELF_CONNECT=%d\n",n);
 if(n==0){int off=0;while(off<(int)sizeof(request)-1){n=((int(*)(int,const void*,int,int))0x457a8c)(fd,request+off,sizeof(request)-1-off,0);if(n<=0)break;off+=n;}LOG("SELF_REQUEST_SENT=%d EXPECTED=%d\n",off,(int)sizeof(request)-1);
 while(total<16384){n=((int(*)(int,void*,int,int))0x457c68)(fd,response,1023,0);if(n<=0)break;response[n]=0;if(total==0&&n>=12&&response[9]=='2'&&response[10]=='0'&&response[11]=='0')ok=1;total+=n;LOG("SELF_RECV_CHUNK=%d DATA=%s\n",n,response);}
 LOG("SELF_HTTP_200=%d SELF_RECEIVED=%d\n",ok,total);}
 ((int(*)(int))0x48fe40)(fd);}
 ((int(*)(int))0x589a2c)(rate*25);
 thread=*(volatile u32*)0x05a86e40u;LOG("NATIVE_URL_HMI_THREAD=%08x\n",thread);
 if(thread<0x03000000u||thread>=0x20000000u){LOG("URL_SKIPPED_thread_not_ready\n");return -2;}
 for(i=0;i<6&&!browser_request_seen;i++){LOG("DIAGNOSTIC_shLoadUrl_ENTER=http://127.0.0.1:18080/phase14.html\n");
 ((void(*)(char*))0x04cb074c)("http://127.0.0.1:18080/phase14.html");
 LOG("DIAGNOSTIC_shLoadUrl_RETURN_no_HTTP_claim\n");((int(*)(int))0x589a2c)(rate*5);}return 0;}
""".replace('@TABLE@',table)
    fixture=r"""{unsigned char*www=((unsigned char*(*)(void))0x04c9b564)();u32 address=(u32)www;
 if(address>=0x03000000u&&address<0x1e000000u&&!(address&3)&&www[0x51391]==1){
 LOG("RUNTIME_PROFILE_SIMULATION_ONLY obj=%08x oldPPP=%u oldflags=%u,%u\n",address,*(u32*)(www+0x50df8),www[0x51397],www[0x51398]);
 *(u32*)(www+0x50df8)=2;www[0x51397]=1;www[0x51398]=0;
 LOG("RUNTIME_PROFILE_SIMULATION_READY=%d PPP=%u flags=%u,%u PAN_DUN_ACTUAL=0 DB_WRITES=0\n",((int(*)(void*))0x04c86c38)(www),*(u32*)(www+0x50df8),www[0x51397],www[0x51398]);
 }else{LOG("PROFILE_SIMULATION_SKIPPED_invalid_instance_or_webgate obj=%08x\n",address);}}
 """
    code=code.replace('@PROFILE@',fixture if simulate_profile else '')
    (out/'guest_loopback.c').write_text(code)
    subprocess.run(['clang','--target=powerpc-none-eabi','-mbig-endian','-m32','-msoft-float','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-pic','-O1','-c',str(out/'guest_loopback.c'),'-o',str(out/'guest_loopback.o')],check=True,capture_output=True)
    # Preserve ELF relocations for the native module loader; explicit entry first.
    (out/'module.ld').write_text('SECTIONS { .text : { *(.text.entry) *(.text*) } .rodata : { *(.rodata*) } .data : { *(.data*) } .bss : { *(.bss*) *(COMMON) } }\n')
    subprocess.run(['ld.lld','-m','elf32ppc','-r','-T',str(out/'module.ld'),str(out/'guest_loopback.o'),'-o',str(out/'guest_loopback.out')],check=True,capture_output=True)
    check=subprocess.run(['readelf','-Ws',str(out/'guest_loopback.out')],check=True,capture_output=True,text=True).stdout
    if 'UND' in '\n'.join(line for line in check.splitlines() if line.strip() and not line.lstrip().startswith('0:')):raise RuntimeError('Unexpected unresolved helper symbol')
    report={'diagnostic_helper':True,'runtime_profile_data_simulation':simulate_profile,'persistent_package_proof':False,'physical_device_access':False,'bound_address':'127.0.0.1:18080','guest_HTTP_success_yet':False,'API_fingerprints':guards,'kernel_sha256':digest(kernel),'module_sha256':digest(out/'guest_loopback.out'),'entry':'phase14_loopback_entry at .text0','execution':'NOT YET EXECUTED; virtualUSB native loader required','symbols':check}
    (out/'guest-loopback-manifest.json').write_text(json.dumps(report,indent=2)+'\n')
    sys.path.insert(0,str(ROOT/'scripts'))
    from smeg_db_inf import crc16
    image=out/'diagnostic-usb.raw'
    with image.open('xb') as f:f.truncate(128*1024*1024)
    subprocess.run(['mkfs.vfat','-F','32','-n','P14_DIAG',str(image)],check=True,capture_output=True)
    media_env=dict(os.environ,MTOOLS_SKIP_CHECK='1')
    for directory in ['FLYING','PHASE14']:
        subprocess.run(['mmd','-i',str(image),'::/'+directory],check=True,capture_output=True,env=media_env)
    payload=(out/'guest_loopback.out').read_bytes()
    body=(f'{crc16(payload):04x}\r\nVER:SMEG5.43.A.R2\r\nTYPE:RELOCABLE\r\nID:0\r\nCOMPRESSED:NO\r\nSIZE:{len(payload)}\r\nENTRY:YES\r\n').encode()
    info=f'{crc16(body):04x}'.encode()+body
    doctor_body=b'0000\r\nACTION:TemporaryBootRom\r\nLOAD_AND_EXECUTE:/bd0/FLYING/guest_loopback.out\r\n'
    doctor=f'{crc16(doctor_body):04x}'.encode()+doctor_body
    for name,data in [('FLYING/guest_loopback.out',payload),('FLYING/guest_loopback.out.inf',info),('FLYING/doctor_smeg_plus_i.inf',doctor)]:
        temp=out/Path(name).name;temp.write_bytes(data)
        subprocess.run(['mcopy','-i',str(image),str(temp),'::/'+name],check=True,capture_output=True,env=media_env)
    report['virtual_USB']=str(image.relative_to(ROOT))
    (out/'guest-loopback-manifest.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k not in ('API_fingerprints','symbols')},indent=2))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, default=SOURCES[0])
    p.add_argument('--output', type=Path, default=OUTROOT/'run01')
    p.add_argument('--prefix', default='/tmp/smeg-p14-browser')
    p.add_argument('--boot-seconds',type=int,default=150)
    p.add_argument('--seconds', type=int, default=300)
    p.add_argument('--simulate-profile',action='store_true',help='Explicit diagnosticRAMcachefixture; neverPAN/DUNproof')
    p.add_argument('--guest-helper-usb',type=Path,help='Explicit diagnostic helperUSB under phase14; not persistent proof')
    p.add_argument('--build-guest-loopback', action='store_true')
    p.add_argument('--run', action='store_true', help='Launch ONE isolated QEMU instance')
    a = p.parse_args()
    source, out = a.source.resolve(), a.output.resolve()
    if source not in [x.resolve() for x in SOURCES]: p.error('Only approved persistent NAND sources accepted')
    if not out.is_relative_to(OUTROOT) or out.exists(): p.error('New output directory inside phase14/browser-network required')
    if not 80 <= a.seconds <= 400: p.error('seconds must be80..400')
    if not 10 <= a.boot_seconds <= a.seconds-60:p.error('boot-seconds must leave at least60seconds for bounded UI/helper observation')
    if a.simulate_profile and a.run and not a.guest_helper_usb:p.error('runtime profile simulation requires explicit diagnostic helperUSB')
    if not a.prefix.startswith('/tmp/smeg-p14-') or '/' in a.prefix[5:]: p.error('Private /tmp/smeg-p14-* prefix required')
    for suffix in ('.qmp','.gdb','.monitor'):
        if Path(a.prefix+suffix).exists(): p.error('Control socket already exists: '+a.prefix+suffix)
    out.mkdir(parents=True)
    if a.build_guest_loopback:
        build_guest_loopback(out,a.simulate_profile); return
    report = {'scope':'private QEMU diagnostic simulation; not persistent-package connectivity proof',
              'source':str(source.relative_to(ROOT)), 'source_sha256_before':digest(source),
              'physical_device_access':False, 'physical_car_io':False,
              'guest_helper_loaded':False, 'guest_memory_writes':False,
              'guest_register_writes':False, 'firmware_instruction_patches':False,
              'PAN_DUN_session_proven':False, 'IP_configuration_proves_connectivity':False,
              'browser_HTTP_request_response_proven':False, 'visible_HTML_load_proven':False,
              'host_loopback_is_guest_loopback':False, 'events':[], 'screenshots':[],
              'limitations':['No virtual phone/BNEP/PPP data-plane adapter is supplied.',
                             'Guest-loopback helper, if requested, is diagnostic injection and is not a PAN/DUN adapter.',
                             'Host HTTP selfcheck is not browser or guest-network evidence.',
                             'A failed browser attempt cannot identify a hardware-decoder limitation.']}
    def save(): (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    board = (ROOT/'emulation/mpc5121e_smeg.c').read_text()
    report['adapter_inventory'] = {'board_NetClientState': 'NetClientState' in board,
        'board_qemu_new_nic': 'qemu_new_nic' in board,
        'HCI_physical_bridge_used':False,
        'existing_test_scope':'test_hci_network validates captured L2CAP/DHCP evidence; it does not create an emulated phone/network'}
    save()
    if not a.run: print(json.dumps(report,indent=2)); return
    subprocess.run(['cp','--reflink=auto','--',str(source),str(out/'nand.raw')],check=True)
    (out/'nand.raw').chmod(0o600)
    http_events=[]
    page=b'<!doctype html><title>SMEG PHASE14 LOOPBACK</title><body style="background:#14763b;color:white"><h1>PHASE14 LOOPBACK HTTP</h1><p>Deterministic diagnostic page.</p></body>'
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            http_events.append({'path':self.path,'client':self.client_address[0],
                'origin':self.headers.get('X-SMEG-Origin','unattributed'), 'time_ns':time.monotonic_ns()})
            self.send_response(200); self.send_header('Content-Type','text/html'); self.send_header('Content-Length',str(len(page)));self.end_headers();self.wfile.write(page)
        def log_message(self,*args): pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    url=f'http://127.0.0.1:{server.server_port}/phase14.html'
    request=urllib.request.Request(url,headers={'X-SMEG-Origin':'host-selfcheck'})
    with urllib.request.urlopen(request,timeout=3) as r:
        report['host_only_positive_control']={'url':url,'HTTP_status':r.status,'body_sha256':hashlib.sha256(r.read()).hexdigest()}
    env={k:v for k,v in os.environ.items() if not k.startswith('SMEG_')}
    env.update(SMEG_NAND=str(out/'nand.raw'),SMEG_SOFT_GLES='1',SMEG_FAST_MEM='1',
        SMEG_GL_RENDERER='software',LP_NUM_THREADS='4',SMEG_DISPLAY='none',
        SMEG_SERIAL='file:'+str(out/'serial.log'),SMEG_RAM_SIZE='512M',
        SMEG_KERNEL=str(ROOT/'artifacts/phase2/package/SMEG_PLUS_UPG/BSP/SMEG_PLUS_256/vxWorks.bin'),
        SMEG_BENCH_HW_PROFILE='int_e', SMEG_APP_VARIANT='audio_bt', SMEG_BSP_VARIANT='256',
        SMEG_BENCH_ECU='1',SMEG_BENCH_VEHICLE='1',SMEG_BENCH_KEY_PROFILE='1',
        SMEG_CONTROL_PREFIX=a.prefix,SMEG_WINDOW_LOG=str(out/'window.log'),SMEG_PIN_THREADS='0')
    if a.guest_helper_usb:
        template=a.guest_helper_usb.resolve()
        if not template.is_relative_to(OUTROOT) or not template.is_file():raise ValueError('Phase14 regular helperUSB required')
        subprocess.run(['cp','--reflink=auto',str(template),str(out/'helper-usb.raw')],check=True)
        env['SMEG_USB_HOST']='1'
        report['diagnostic_helper_requested']=True
        report['guest_helper_loaded']=False
    cmd=['bash','emulation/launch_ui.sh','-nic','none','-D',str(out/'qemu.log'),
         '-action','reboot=reset','-name','Phase14 offline browser diagnostic']
    if a.guest_helper_usb:cmd+=['-drive','if=none,id=p14helper,file='+str(out/'helper-usb.raw')+',format=raw']
    report['instrumentation']='Read-only Z1 hardware breakpoints; timing affected, no guest instruction/RAM patch'
    report['launch']={'command':cmd,'environment':{k:v for k,v in env.items() if k.startswith('SMEG_')},'prefix':a.prefix}
    proc=None;q=None;r=None;armed=set();stopped=False;counts={};started=time.monotonic()
    try:
        with (out/'window.log').open('w') as window:
            proc=subprocess.Popen(cmd,cwd=ROOT,env=env,stdout=window,stderr=subprocess.STDOUT)
        deadline=started+a.seconds
        while not Path(a.prefix+'.qmp').exists():
            if proc.poll() is not None: raise RuntimeError('QEMU exited before socket ready')
            if time.monotonic()>started+15: raise TimeoutError('QMP startup timeout')
            time.sleep(.1)
        q=QMP(a.prefix+'.qmp')
        report['qemu_info_network']=q.call('human-monitor-command',{'command-line':'info network'})
        while time.monotonic()<started+a.boot_seconds:
            if proc.poll() is not None: raise RuntimeError('QEMU exited during native boot')
            time.sleep(.2)
        def shot(name):
            f=out/(name+'.png');q.call('screendump',{'filename':str(f),'format':'png'});report['screenshots'].append(str(f.relative_to(ROOT)));save()
        shot('boot')
        q.close();q=None
        subprocess.run([sys.executable,'emulation/ui_control.py','--socket',a.prefix+'.qmp','--panel','web','--car-fmux','--settle','2','--screenshot',str(out/'native-connect-apps.png')],cwd=ROOT,check=True,capture_output=True)
        subprocess.run([sys.executable,'emulation/ui_control.py','--socket',a.prefix+'.qmp','--click','30','230','--settle','3','--screenshot',str(out/'native-internet-menu.png')],cwd=ROOT,check=True,capture_output=True)
        report['screenshots'] += [str((out/name).relative_to(ROOT)) for name in ('native-connect-apps.png','native-internet-menu.png')]
        q=QMP(a.prefix+'.qmp')
        q.call('stop');stopped=True;r=RSP(a.prefix+'.gdb');r.req('qSupported');r.req('?');r.req('Qqemu.PhyMemMode:1');r.s.settimeout(.08)
        for pc in POINTS:
            if r.req(f'Z1,{pc:x},4')=='OK':armed.add(pc)
        r.send('c');stopped=False
        def pump(seconds):
            nonlocal stopped
            end=min(time.monotonic()+seconds,deadline)
            while time.monotonic()<end:
                try: stop=r.recv();stopped=True
                except socket.timeout: continue
                pc=r.reg(64)
                if pc not in armed: raise RuntimeError('Unexpected debugger stop '+hex(pc))
                event={'function':POINTS[pc],'PC':hex(pc),'elapsed':round(time.monotonic()-started,3)}
                if pc in (0x4c86c38,0x4c86cec):
                    obj=r.reg(3);event['object']=hex(obj)
                    raw=r.req(f'm{obj+0x51390:x},9');event['availability_hex']=raw
                    raw=r.req(f'm{obj+0x50df8:x},4');event['PPP_state']=int(raw,16) if not raw.startswith('E') else raw
                else:
                    event['arguments']=[hex(r.reg(n)) for n in (3,4,5,6)]
                    if pc==0x4cb074c:event['char_URL']=r.string(r.reg(3))
                    if pc==0x4d1e938:
                        obj=r.reg(3)
                        event['webView_pointer']=r.req(f'm{obj+0x14:x},4')
                        event['initialized_byte']=r.req(f'm{obj+0x1c:x},1')
                    if pc in (0x205b8bc,0x4d1e938):event['QString_argument_bytes']=r.req(f'm{r.reg(4):x},10')
                report['events'].append(event);save();r.req(f'z1,{pc:x},4');armed.remove(pc)
                r.req('s');counts[pc]=counts.get(pc,0)+1
                if counts[pc]<8:r.req(f'Z1,{pc:x},4');armed.add(pc)
                r.send('c');stopped=False
        def tap(x,y):
            q.call('input-send-event',{'events':[{'type':'abs','data':{'axis':'x','value':round(x*32767/799)}},{'type':'abs','data':{'axis':'y','value':round(y*32767/479)}},{'type':'btn','data':{'button':'left','down':True}}]});pump(.18)
            q.call('input-send-event',{'events':[{'type':'btn','data':{'button':'left','down':False}}]})
        tap(400,150);pump(7);shot('browser-attempt')
        if a.guest_helper_usb:
            report['no_USB_before_explicit_insertion']=q.call('human-monitor-command',{'command-line':'info usb'})
            report['helper_hotplug']=q.call('device_add',{'driver':'usb-storage','id':'p14helper','drive':'p14helper','removable':True})
            if a.simulate_profile:
                pump(12);tap(222,82);pump(2);tap(400,150);pump(12);shot('browser-profile-simulated');pump(32)
            else:pump(55)
            shot('after-diagnostic-loopback')
        report['final_guest_status']=q.call('query-status')
    except Exception as exc:
        report['error']=str(exc)
    finally:
        if r:
            try:
                r.s.settimeout(2)
                if not stopped:r.s.sendall(b'\x03');r.recv();stopped=True
                for pc in armed:r.req(f'z1,{pc:x},4')
                r.req('D');r.s.close();report['debugger_cleanup']='All breakpoints removed; detached/resumed'
            except Exception as exc:report['debugger_cleanup_error']=str(exc)
        if q:
            try:q.call('quit')
            except (EOFError,OSError):pass
            q.close()
        if proc:
            try:proc.wait(timeout=8)
            except subprocess.TimeoutExpired:proc.terminate();proc.wait(timeout=5)
        server.shutdown();server.server_close();thread.join(timeout=3)
        if a.guest_helper_usb and (out/'helper-usb.raw').exists():
            result=subprocess.run(['mcopy','-i',str(out/'helper-usb.raw'),'::/PHASE14/loopback.log',str(out/'guest-loopback.log')],capture_output=True,text=True,env=dict(os.environ,MTOOLS_SKIP_CHECK='1'))
            report['guest_log_extraction_returncode']=result.returncode
            if result.returncode==0:
                log=(out/'guest-loopback.log').read_text(errors='replace');report['guest_loopback_log']=log
                report['native_guest_TCP_HTTP_selfcheck_proven']='SELF_HTTP_200=1' in log and 'User-Agent: P14NativeSelfCheck' in log and 'CANARY P14-HTTP-18080' in log
                report['guest_helper_loaded']=True
                if 'RUNTIME_PROFILE_SIMULATION_READY=1' in log:
                    report['guest_memory_writes']=True;report['runtime_profile_data_simulation']=True;report['persistent_package_proof']=False
                report['native_guest_loopback_listener_proven']='BIND127.0.0.1:18080=0' in log and 'LISTEN=0' in log
                match=re.search(r'BODY_SENT=(\d+) EXPECTED=(\d+)',log)
                report['browser_HTTP_request_response_proven']=bool('REQUEST=GET /phase14.html' in log and match and int(match[1])>0 and match[1]==match[2])
                report['guest_loopback_not_PAN_or_DUN']=True
        report['host_HTTP_requests']=http_events
        report['guest_HTTP_request_response_proven']=bool(report.get('native_guest_TCP_HTTP_selfcheck_proven') or report['browser_HTTP_request_response_proven'])
        report['guest_HTTP_requests_verified']=int(bool(report.get('native_guest_TCP_HTTP_selfcheck_proven')))+int(report['browser_HTTP_request_response_proven'])
        report['source_sha256_after']=digest(source)
        report['source_unchanged']=report['source_sha256_after']==report['source_sha256_before']
        report['private_VM_stopped']=proc is not None and proc.poll() is not None
        report['elapsed_seconds']=round(time.monotonic()-started,2)
        serial=(out/'serial.log').read_text(errors='replace') if (out/'serial.log').exists() else ''
        report['exception_markers']=[line for line in serial.splitlines() if any(x in line for x in ('Exception number','Exception current','workQPanic'))][:15]
        report['conclusion']=('Native guest-loopback HTTP request and complete response observed; visible rendering requires separate screenshot inspection. This is not PAN/DUN or persistent-package connectivity proof.' if report['browser_HTTP_request_response_proven'] else ('Native guest-loopback TCP/HTTP selfcheck succeeded, while browser HTML loading remains unproven. Inspect GUI URL receiver/widget initialization; do not infer decoder limitations.' if report.get('native_guest_TCP_HTTP_selfcheck_proven') else 'No guest HTTP load demonstrated. Distinguish native browser/asset/init faults from transport; a missing request alone does not prove a decoder limitation.'))
        save()
    print(json.dumps({k:v for k,v in report.items() if k not in ('launch','events')},indent=2))

if __name__=='__main__':main()
