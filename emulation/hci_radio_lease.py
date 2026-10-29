#!/usr/bin/env python3
"""Lease one Linux Bluetooth controller to an unprivileged H4 bridge, then restore BlueZ."""
import argparse,json,os,pwd,socket,subprocess,sys,time,signal,re,stat,configparser,fcntl
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent

def run(*args,timeout=10,check=True):
    r=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
    if check and r.returncode:raise RuntimeError(r.stderr.strip() or r.stdout.strip())
    return r

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--controller',type=int,default=0)
    p.add_argument('--seconds',type=int,default=180)
    p.add_argument('--case',default='hci_live')
    p.add_argument('--mode',choices=['live','infineon-live','diagnostic'],default='live')
    p.add_argument('--plan',action='store_true')
    p.add_argument('--reuse-host-bond',action='store_true')
    a=p.parse_args()
    if not 0<=a.controller<=15 or not 30<=a.seconds<=900:p.error('controller0..15, lease30..900seconds')
    if not re.fullmatch('[a-z0-9_-]+',a.case):p.error('invalid case')
    if a.reuse_host_bond and a.mode!='infineon-live':p.error('Host bond reuse requires infineon-live')
    uid=int(os.environ.get('PKEXEC_UID',os.environ.get('SUDO_UID',os.getuid())))
    if not uid:p.error('Invoke through pkexec/sudo from the desktop user account')
    account=pwd.getpwuid(uid);case=ROOT/'artifacts/phase4/runs'/a.case
    plan={'controller':f'hci{a.controller}','desktop_user':account.pw_name,'seconds':a.seconds,
          'socket':str(case/'hci.sock'),'mode':a.mode,'physical_car_access':False,
          'reuse_existing_host_bond':a.reuse_host_bond,
          'temporary_effect':'Disconnect host Bluetooth links on this adapter; guest gets exclusive HCI control',
          'restore':'Close user channel, restore adapter power and previous PAN profiles',
          'privileges':'Radio opened by parent; bridge child drops to desktop UID before reading guest packets'}
    print(json.dumps(plan),flush=True)
    if a.plan:return
    if os.geteuid()!=0:p.error('Administrator authentication is required to bind HCI_CHANNEL_USER')
    if not case.is_dir():p.error('Prepare the isolated case directory before authentication')
    def stop(signum, frame): raise SystemExit(0)
    signal.signal(signal.SIGTERM, stop);signal.signal(signal.SIGINT, stop)
    adapter=f'/org/bluez/hci{a.controller}';radio=None;child=None;powered=False;profiles=[];connected=[];bond_fd=None
    try:
        if a.reuse_host_bond:
            peer='22:22:4D:F1:4E:5E'
            adapter_address=run('busctl','--system','get-property','org.bluez',adapter,'org.bluez.Adapter1','Address').stdout.split('"')[1].upper()
            if not re.fullmatch('[0-9A-F]{2}(:[0-9A-F]{2}){5}',adapter_address):raise RuntimeError('Invalid adapter address')
            device=adapter+'/dev_'+peer.replace(':','_')
            if run('busctl','--system','get-property','org.bluez',device,'org.bluez.Device1','Paired').stdout.strip()!='b true':
                raise RuntimeError('Known OnePlus target is not paired to the host')
            config=configparser.ConfigParser()
            with (Path('/var/lib/bluetooth')/adapter_address/peer/'info').open() as source:config.read_file(source)
            key=config['LinkKey']['Key']
            if not re.fullmatch('[0-9A-Fa-f]{32}',key):raise RuntimeError('Invalid stored BR/EDR key')
            bond_fd=os.memfd_create('smeg-existing-bond',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
            os.write(bond_fd,bytes.fromhex(key));os.lseek(bond_fd,0,os.SEEK_SET)
            fcntl.fcntl(bond_fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SEAL)
            print(json.dumps({'existing_host_bond_loaded':True,'peer':peer,'key_type':config['LinkKey'].getint('Type'),
                              'storage':'sealed anonymous memory; no key printed or written'}),flush=True)
        powered=run('busctl','--system','get-property','org.bluez',adapter,'org.bluez.Adapter1','Powered').stdout.strip()=='b true'
        for line in run('bluetoothctl','devices','Connected').stdout.splitlines():
            match=re.match(r'Device ([0-9A-Fa-f:]{17}) ',line)
            if match:connected.append(match.group(1))
        for line in run('nmcli','-t','-f','UUID,TYPE','connection','show','--active').stdout.splitlines():
            uid_type=line.rsplit(':',1)
            if len(uid_type)==2 and uid_type[1]=='bluetooth':profiles.append(uid_type[0])
        run('busctl','--system','set-property','org.bluez',adapter,'org.bluez.Adapter1','Powered','b','false')
        radio=socket.socket(socket.AF_BLUETOOTH,socket.SOCK_RAW,socket.BTPROTO_HCI)
        radio.bind((a.controller,1))
        def drop_privileges():
            os.setgroups([]);os.setgid(account.pw_gid);os.setuid(uid)
        if a.mode=='diagnostic':
            cmd=[sys.executable,str(ROOT/'emulation/hci_radio_diagnostic.py'),
                 '--radio-fd',str(radio.fileno()),'--output',str(case/'radio-diagnostic.json')]
        else:
            cmd=[sys.executable,str(ROOT/'emulation/hci_bridge.py'),'--mode',a.mode,'--controller',str(a.controller),
                 '--radio-fd',str(radio.fileno()),'--socket',str(case/'hci.sock'),'--log',str(case/'hci.jsonl')]
        inherited=(radio.fileno(),)
        if bond_fd is not None:
            cmd+=['--bond-fd',str(bond_fd),'--bond-peer',peer];inherited+=(bond_fd,)
        child=subprocess.Popen(cmd,pass_fds=inherited,preexec_fn=drop_privileges,cwd=ROOT)
        # Parent retains its descriptor solely to guarantee automatic cleanup.
        try:child.wait(timeout=a.seconds)
        except subprocess.TimeoutExpired:child.terminate();child.wait(timeout=5)
    finally:
        if child and child.poll() is None:child.terminate();child.wait(timeout=5)
        if radio:radio.close()
        if bond_fd is not None:os.close(bond_fd)
        endpoint=case/'hci.sock'
        try:
            st=endpoint.lstat()
            if stat.S_ISSOCK(st.st_mode) and st.st_uid==uid:endpoint.unlink()
        except FileNotFoundError:pass
        if powered:
            restored=False
            for _ in range(40):
                r=run('busctl','--system','set-property','org.bluez',adapter,'org.bluez.Adapter1','Powered','b','true',check=False)
                if not r.returncode:restored=True;break
                time.sleep(.125)
            print(json.dumps({'adapter_power_restored':restored}),flush=True)
            if restored:
                for address in connected:
                    r=run('bluetoothctl','--timeout','5','connect',address,timeout=8,check=False)
                    print(json.dumps({'restored_device':address,'success':not r.returncode}),flush=True)
                for profile in profiles:
                    r=run('nmcli','--wait','15','connection','up','uuid',profile,timeout=18,check=False)
                    print(json.dumps({'restored_pan_uuid':profile,'success':not r.returncode}),flush=True)
if __name__=='__main__':main()
