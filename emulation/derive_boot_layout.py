#!/usr/bin/env python3
"""Derive boot and HCF device evidence from supplied raw SMEG VxWorks images.
Requires capstone; writes evidence only and never changes firmware.
"""
import argparse
import hashlib
import json
import re
import struct
from pathlib import Path
import capstone
BASE = 0x200000

def derive(path):
    blob = path.read_bytes()
    def string(address):
        offset = address - BASE
        if not 0 <= offset < len(blob):
            return None
        end = blob.find(b'\0', offset, min(offset + 200, len(blob)))
        if end < 0:
            return None
        raw = blob[offset:end]
        if not raw or any(c < 32 or c > 126 for c in raw):
            return None
        return raw.decode('ascii')
    def record(offset):
        if offset < 0 or offset + 20 > len(blob):
            return None
        zero, name, address, zero2, kind = struct.unpack_from('>IIIII', blob, offset)
        if zero or zero2 or kind not in (0x100,0x300,0x500,0x700,0x900,0xb00,0xd00,0xf00,0x1100):
            return None
        text = string(name)
        return {'name':text, 'address':address,'kind':kind,'record_file_offset':offset} if text else None
    target = blob.find(b'usrInit\0')
    if target < 0:
        raise ValueError('usrInit symbol string absent')
    candidates = [m.start()-4 for m in re.finditer(re.escape(struct.pack('>I',BASE+target)),blob)]
    seed = next(off for off in candidates if (r:=record(off)) and r['name']=='usrInit' and r['kind']==0x500)
    start = seed
    while record(start-20):
        start -= 20
    symbols=[]
    off=start
    while (r:=record(off)):
        symbols.append(r)
        off+=20
    sym={r['name']:r for r in symbols}
    md=capstone.Cs(capstone.CS_ARCH_PPC,capstone.CS_MODE_32|capstone.CS_MODE_BIG_ENDIAN)
    def disasm(address,length):
        return [{'address':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in md.disasm(blob[address-BASE:address-BASE+length],address)]
    selected=['_sysInit','usrInit','sysStart','vxSdaInit','sysHwInit','sysHwInit2','vxImmrIsbGet','vxImmrDevGet','usrSerialInit','bspSerialChanGet','PscSioInitFifo','hcfDeviceList','hcfDeviceNum','sysPhysMemDesc','sysPhysMemDescNumEnt']
    out={'path':str(path),'sha256':hashlib.sha256(blob).hexdigest(),'load_base':hex(BASE),'load_base_evidence':'Contiguous symbol records resolve name pointers with this base; initial wrapper branch targets named usrInit.','symbol_table':{'file_offset':hex(start),'entry_size':20,'count':len(symbols)},'symbols':{n:{'address':hex(sym[n]['address']),'record_file_offset':hex(sym[n]['record_file_offset']),'kind':hex(sym[n]['kind'])} for n in selected if n in sym},'disassembly':{}}
    for name,length in [('_sysInit',0x290),('usrInit',0x9c),('sysStart',0x6c),('vxSdaInit',0x14),('vxImmrIsbGet',0x18),('sysHwInit',0x80),('usrSerialInit',0x148),('PscSioInitFifo',0x68)]:
        if name in sym:
            out['disassembly'][name]=disasm(sym[name]['address'],length)
    devices=[]
    count=struct.unpack_from('>I',blob,sym['hcfDeviceNum']['address']-BASE)[0]
    for i in range(count):
        a=sym['hcfDeviceList']['address']+i*24
        name,unit,bustype,flags,nresources,resptr=struct.unpack_from('>6I',blob,a-BASE)
        resources=[]
        for j in range(nresources):
            key,kind,value=struct.unpack_from('>III',blob,resptr-BASE+j*12)
            resources.append({'key':string(key),'type_raw':kind,'value':hex(value),'string_value':string(value) if kind==1 else None})
        devices.append({'record_address':hex(a),'name':string(name),'unit':unit,'bus_type_raw':bustype,'flags_raw':flags,'resources':resources})
    out['hcf_devices']=devices
    fifo = next(d for d in devices if d['name']=='m512xFifoc')
    fifo_input = int(next(r['value'] for r in fifo['resources'] if r['key']=='input'),16)
    fifo_count = int(next(r['value'] for r in fifo['resources'] if r['key']=='inputTableSize'),16)
    out['fifo_input_mapping'] = []
    for i in range(fifo_count):
        physical,driver,logical,flags=struct.unpack_from('>IIII',blob,fifo_input-BASE+i*16)
        out['fifo_input_mapping'].append({'physical_psc':physical,'driver':string(driver),'logical_channel':logical,'flags_raw':flags})
    out['physical_memory_descriptors_raw']={'address':hex(sym['sysPhysMemDesc']['address']),'declared_count':struct.unpack_from('>I',blob,sym['sysPhysMemDescNumEnt']['address']-BASE)[0],'words_hex':[hex(v) for v in struct.unpack_from('>48I',blob,sym['sysPhysMemDesc']['address']-BASE)],'note':'Raw words retained; descriptor ABI/stride not asserted.'}
    mounts=[]
    for name in [b'/SYSTEM\0',b'/SYSTEM_DATA\0',b'/SYSTEM_TMP_DATA\0',b'/USER_DATA\0',b'/USER_DATA_BACKUP\0',b'/EXTENDED_PARTITION\0',b'FFXDisk1\0',b'FFXDisk2\0',b'FFXDisk3\0',b'FFXDisk4\0',b'FFXDisk5\0',b'FFXDisk6\0']:
        pos=0
        while (pos:=blob.find(name,pos))>=0:
            mounts.append({'string':name[:-1].decode(),'file_offset':hex(pos),'address':hex(BASE+pos)})
            pos+=len(name)
    out['storage_strings']=mounts
    return out

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package',type=Path,default=Path('artifacts/phase2/package/SMEG_PLUS_UPG'))
    parser.add_argument('--output',type=Path,default=Path('emulation/boot_layout.json'))
    args=parser.parse_args()
    result={'evidence_source':'local original package, static instructions and contiguous VxWorks symbols','kernels':[derive(args.package/'BSP'/f'SMEG_PLUS_{variant}'/'vxWorks.bin') for variant in ['256','512']], 'experimental_boot':{'preferred_entry_512':'0x00200038','reason':'_sysInit assembly initializes MSR/segments/BATs/stack then branches usrInit; entry at file0 needs a preexisting stack. No claim this is physical reset.','start_type_r3':0,'stack_pointer_set_by_guest':'0x001ffff0','r2_set_by_vxSdaInit':'0x007a5f80','r13_set_by_vxSdaInit':'0x0086dbb0','bss_clear_512':['0x008671f0','0x008de750'],'immr_base':'0x80000000','immr_spr':638,'immr_confidence':'high: MMIO literal addresses and UART resource tables; SPR initial state still emulator assumption','console_channel':3,'console_baud':115200,'console_psc_candidate':9,'console_psc_confidence':'channel3 selection and baud are instruction-proven; mapping channel index to HCF unit order requires runtime confirmation','clock_warning':'Clock callback0x20e59c divides by ((MMIO[0x80000f0c]>>23)&7); generic zero MMIO causes division by zero. Clock source0x20e494 reads0x80000e00 and table lookups at0x7a0310/0x7a0320.','storage_limit':'Mount names and FFXDisk strings do not establish NAND offsets or a ready-to-attach disk image.'}}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print("Wrote", args.output, "kernels", len(result["kernels"]))
if __name__=='__main__':
    main()
