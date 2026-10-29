#!/usr/bin/env python3
"""Populate an existing native SMEG FlashFX disk1 on a COPY using valid VBF allocations.
Narrowly targets the observed 2048+64 NAND geometry and native 2MiB FAT12 disk1.
Never edits a source image, BBM maps, VBF unit headers, or RTOS instructions.
Requires mtools mcopy/mdir. Native reboot validation is required after injection.
"""
import argparse,hashlib,json,mmap,shutil,struct,subprocess,tempfile
from pathlib import Path
PAGE=2048
OOB=64
STRIDE=PAGE+OOB
PAGES_PER_UNIT=64
SIGNATURE=bytes.fromhex('ccdd444c5f4653342e3030ffffffffff')

def decode_tag(oob):
    a,b,c,d=oob[48:52]
    if c!=0xf0 or d!=((~(a^b))&255):return None
    tag=a|(b<<8)
    return tag&0x3fff if tag&0xc000==0x4000 else None

def tag_oob(sector):
    tag=0x4000|sector;a=tag&255;b=tag>>8
    out=bytearray(b'\xff'*OOB)
    out[48:54]=bytes([a,b,0xf0,(~(a^b))&255,0xff,0xf0])
    return out

def scan(mm,start_page,units):
    headers=[];records=[];free=[]
    for unit in range(units):
        page=start_page+unit*PAGES_PER_UNIT;offset=page*STRIDE
        raw=mm[offset:offset+56]
        if not raw.startswith(SIGNATURE):continue
        page_size=struct.unpack_from('<H',raw,0x2a)[0]
        units_per_region=struct.unpack_from('<H',raw,0x2c)[0]
        pages_per_unit=struct.unpack_from('<H',raw,0x32)[0]
        region_bytes=page_size*units_per_region*pages_per_unit
        if page_size!=PAGE or not region_bytes:raise ValueError('unexpected native VBF geometry')
        address=struct.unpack_from('<I',raw,0x10)[0]
        if address==0xffffffff:continue
        region=address//region_bytes
        seq=struct.unpack_from('<I',raw,0x1c)[0]
        headers.append({'unit':unit,'page':page,'region':region,'sequence':seq,'region_logical_pages':region_bytes//PAGE,'header_sha256':hashlib.sha256(raw).hexdigest()})
        for index in range(1,PAGES_PER_UNIT):
            p=page+index;o=p*STRIDE;data=mm[o:o+PAGE];spare=mm[o+PAGE:o+STRIDE]
            if data==b'\xff'*PAGE and spare==b'\xff'*OOB:
                free.append({'page':p,'unit':unit,'region':region,'sequence':seq,'region_logical_pages':region_bytes//PAGE})
                continue
            local=decode_tag(spare)
            if local is not None and local<region_bytes//PAGE:
                records.append({'page':p,'unit':unit,'region':region,'sequence':seq,'sector':region*(region_bytes//PAGE)+local,'local_sector':local})
    # Native record sequence and append order establish newest allocation.
    latest={}
    for record in sorted(records,key=lambda r:(r['sequence'],r['page'])):latest[record['sector']]=record
    return headers,latest,free

def extract(mm,latest,sectors=1024):
    image=bytearray(sectors*PAGE)
    for sector,record in latest.items():
        if sector<sectors:image[sector*PAGE:(sector+1)*PAGE]=mm[record['page']*STRIDE:record['page']*STRIDE+PAGE]
    if image[510:512]!=b'\x55\xaa':raise ValueError('native FAT boot signature absent')
    bps=struct.unpack_from('<H',image,11)[0];nsec=struct.unpack_from('<H',image,19)[0]
    if bps!=PAGE or nsec!=sectors or image[54:62]!=b'FAT12   ':raise ValueError('only observed native 2MiB FAT12 disk1 supported')
    return image

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--input',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--source','--payload',dest='payload',type=Path,default=Path('artifacts/phase3/payloads/SYSTEM_DATA'))
    ap.add_argument('--start-page',type=int,default=91840)
    ap.add_argument('--units',type=int,default=18)
    ap.add_argument('--report',type=Path)
    args=ap.parse_args()
    if args.output.exists():ap.error('output must not exist')
    if args.input.resolve()==args.output.resolve():ap.error('source and output must differ')
    if not shutil.which('mcopy') or not shutil.which('mdir'):ap.error('mtools required')
    files=sorted(p for p in args.payload.iterdir() if p.is_file())
    names={p.name for p in files}
    if not {'ssm_boot.out','ssm_boot.out.inf'}<=names or names-{'ssm_boot.out','ssm_boot.out.inf','startApp.txt'}:ap.error('payload must contain native ssm_boot.out/.inf and optional startApp.txt')
    if 'startApp.txt' in names and (args.payload/'startApp.txt').stat().st_size!=0:ap.error('generated startApp.txt marker must be empty')
    with args.input.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as mm:
        headers,latest,free=scan(mm,args.start_page,args.units)
        original=extract(mm,latest)
    with tempfile.TemporaryDirectory(prefix='smeg-native-fat-') as temp:
        fat=Path(temp)/'system_data.fat';fat.write_bytes(original)
        for p in files:subprocess.run(['mcopy','-o','-i',str(fat),str(p),'::/'],check=True,capture_output=True)
        listing=subprocess.run(['mdir','-i',str(fat),'::/'],check=True,capture_output=True,text=True).stdout
        changed=fat.read_bytes()
        changed_sectors=[i for i in range(1024) if changed[i*PAGE:(i+1)*PAGE]!=original[i*PAGE:(i+1)*PAGE]]
        # Existing sectors must be appended within their original unit so their
        # newer versions are unambiguous without altering native header sequence.
        allocations=[];available=list(free)
        for sector in changed_sectors:
            old=latest.get(sector)
            matches=[p for p in available if p['region']==0 and (old is None or p['unit']==old['unit'])]
            if not matches:raise SystemExit('insufficient compatible erased pages; refusing speculative VBF metadata edits')
            selected=min(matches,key=lambda p:p['page']);available.remove(selected)
            allocations.append({'sector':sector,'page':selected['page'],'unit':selected['unit'],'previous_page':old['page'] if old else None})
        args.output.parent.mkdir(parents=True,exist_ok=True)
        subprocess.run(['cp','--reflink=auto',str(args.input),str(args.output)],check=True)
        with args.output.open('r+b') as f,mmap.mmap(f.fileno(),0) as mm:
            before=[mm[h['page']*STRIDE:h['page']*STRIDE+56] for h in headers]
            for record in allocations:
                s=record['sector'];o=record['page']*STRIDE
                if mm[o:o+STRIDE]!=b'\xff'*STRIDE:raise ValueError('chosen page is not erased')
                mm[o:o+PAGE]=changed[s*PAGE:(s+1)*PAGE]
                mm[o+PAGE:o+STRIDE]=tag_oob(s)
            after=[mm[h['page']*STRIDE:h['page']*STRIDE+56] for h in headers]
            if before!=after:raise ValueError('native headers changed unexpectedly')
            _,updated,_=scan(mm,args.start_page,args.units)
            if extract(mm,updated)!=changed:raise ValueError('VBF reread does not match populated FAT')
            mm.flush()
        # Read files back through the rebuilt logical view and mtools, checking
        # original package hashes rather than only FAT metadata consistency.
        with args.output.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as mm:
            _,verified_map,_=scan(mm,args.start_page,args.units)
            fat.write_bytes(extract(mm,verified_map))
        verified_files=[]
        for payload in files:
            target=Path(temp)/('verify-'+payload.name)
            subprocess.run(['mcopy','-i',str(fat),'::/'+payload.name,str(target)],check=True,capture_output=True)
            original_hash=hashlib.sha256(payload.read_bytes()).hexdigest()
            readback_hash=hashlib.sha256(target.read_bytes()).hexdigest()
            if original_hash!=readback_hash:raise ValueError('file readback hash mismatch: '+payload.name)
            verified_files.append({'name':payload.name,'sha256':readback_hash,'matches_source':True})
        report={'source':str(args.input),'output':str(args.output),'scope':'disk1 SYSTEM_DATA only; copy modified','native_headers_preserved':True,'changed_logical_sectors':len(allocations),'allocations':allocations,'file_payloads':[{'name':p.name,'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in files],'readback_files':verified_files,'fat_sha256':hashlib.sha256(changed).hexdigest(),'mtools_listing':listing,'native_boot_validation':'pending: guest must mount and read file names/content without reformatting'}
        report_path=args.report or args.output.with_suffix(args.output.suffix+'.json')
        report_path.write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps({'output':str(args.output),'sectors_appended':len(allocations),'report':str(report_path)}))
        print(listing)
if __name__=='__main__':main()
