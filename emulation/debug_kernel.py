#!/usr/bin/env python3
"""Bounded local kernel disassembly and streamed QEMU trace triage; no firmware edits."""
import argparse,bisect,json,re,struct
from collections import Counter,deque
from pathlib import Path
import capstone
BASE=0x200000

def load_symbols(blob):
    symbols=[]
    for off in range(0x622024,len(blob)-19,20):
        zero,pointer,address,zero2,kind=struct.unpack_from('>IIIII',blob,off)
        if zero or zero2 or not BASE<=pointer<BASE+len(blob):
            break
        end=blob.find(b'\0',pointer-BASE,min(pointer-BASE+200,len(blob)))
        if end<0:break
        raw=blob[pointer-BASE:end]
        if not raw or any(v<32 or v>126 for v in raw):break
        symbols.append({'name':raw.decode(),'address':address,'kind':kind})
    return symbols

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kernel',type=Path,default=Path('artifacts/phase2/package/SMEG_PLUS_UPG/BSP/SMEG_PLUS_512/vxWorks.bin'))
    p.add_argument('--address',type=lambda x:int(x,0))
    p.add_argument('--symbol')
    p.add_argument('--length',type=lambda x:int(x,0),default=128)
    p.add_argument('--trace',type=Path)
    p.add_argument('--limit',type=int,default=8)
    args=p.parse_args()
    if args.length<1 or args.length>4096:p.error('--length must be 1..4096')
    blob=args.kernel.read_bytes();symbols=load_symbols(blob)
    funcs=sorted((s for s in symbols if s['kind']==0x500),key=lambda s:s['address']);addresses=[s['address'] for s in funcs]
    def resolve(address):
        i=bisect.bisect_right(addresses,address)-1
        return 'unknown' if i<0 else '{}+0x{:x}'.format(funcs[i]['name'],address-funcs[i]['address'])
    address=args.address
    if args.symbol:
        matches=[s for s in symbols if s['name']==args.symbol]
        if len(matches)!=1:p.error('symbol missing or ambiguous')
        address=matches[0]['address']
    if address is not None:
        if not BASE<=address<BASE+len(blob):p.error('address outside file-backed kernel')
        md=capstone.Cs(capstone.CS_ARCH_PPC,capstone.CS_MODE_32|capstone.CS_MODE_BIG_ENDIAN)
        print(json.dumps({'address':hex(address),'symbol':resolve(address)}))
        for i in md.disasm(blob[address-BASE:address-BASE+args.length],address):
            print('0x{:08x}: {:8s} {}'.format(i.address,i.mnemonic,i.op_str))
    if args.trace:
        prior=deque(maxlen=10);events=[];counts=Counter();blocks=deque(maxlen=12);mmio=Counter()
        with args.trace.open(errors='replace') as f:
            for line in f:
                if 'Invalid read at addr' in line or 'Invalid write at addr' in line:
                    counts['invalid_memory_accesses']+=1
                    if counts['invalid_memory_accesses']==1:events.append({'event':'first invalid access','line':line.strip(),'prior':list(prior)})
                if line.startswith('0x') and ':' in line:
                    try:
                        pc=int(line.split(':')[0],16);blocks.append({'pc':hex(pc),'symbol':resolve(pc)})
                    except ValueError:pass
                if any(t in line for t in ['invalid/unsupported opcode','Raise exception','exception=']):
                    counts['exception_markers']+=1
                    if len(events)<args.limit:events.append({'event':'exception marker','line':line.strip(),'prior':list(prior)})
                if 'SMEG MMIO' in line:
                    counts['mmio_accesses']+=1
                    match=re.search(r'addr=(0x[0-9a-f]+)',line)
                    if match:mmio[match.group(1)]+=1
                prior.append(line.rstrip())
        print(json.dumps({'trace':str(args.trace),'counts':counts,'events':events,'last_blocks':list(blocks),'mmio_most_common':mmio.most_common(20)},indent=2))
if __name__=='__main__':main()
