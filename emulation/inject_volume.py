#!/usr/bin/env python3
"""Discover and populate existing native VBF/FAT volumes on a separate NAND image.
Original BBM, VBF headers, allocation tags of existing sectors and firmware are
preserved. Existing allocated data pages are replaced offline; missing sectors
receive new valid allocations in their existing VBF region. Native reboot is
required to validate the resulting image. No mount results are fabricated.
"""
import argparse,hashlib,json,mmap,os,shutil,stat,struct,subprocess,tempfile
from collections import defaultdict
from pathlib import Path
from inject_vbf import PAGE,OOB,STRIDE,PAGES_PER_UNIT,SIGNATURE,decode_tag,tag_oob

def run(command, **kwargs):
    try:
        # Native mounted FAT16 snapshots clear the clean bit in reserved FAT entry1.
        # mtools mistakes that legitimate state for a broken FAT; this setting
        # skips its preliminary check without altering native filesystem bytes.
        environment=dict(os.environ)
        if command[0] in ('mcopy','mdir'):
            environment['MTOOLS_SKIP_CHECK']='1'
        return subprocess.run(command,check=True,capture_output=True,env=environment,**kwargs)
    except subprocess.CalledProcessError as exc:
        stderr=exc.stderr.decode(errors='replace') if isinstance(exc.stderr,bytes) else exc.stderr
        stdout=exc.stdout.decode(errors='replace') if isinstance(exc.stdout,bytes) else exc.stdout
        raise SystemExit('External command failed: '+str(command)+'\n'+(stderr or '')+'\n'+(stdout or '')) from exc

def discover(mm):
    groups=defaultdict(list)
    for page in range(0,len(mm)//STRIDE,PAGES_PER_UNIT):
        off=page*STRIDE;raw=mm[off:off+56]
        if not raw.startswith(SIGNATURE):continue
        page_size,units_per_region=struct.unpack_from('<HH',raw,0x2a)
        physical_pages,pages_per_unit=struct.unpack_from('<HH',raw,0x30)
        address,erase_count,serial,seq,total_units=struct.unpack_from('<5I',raw,0x10)
        region_pages=units_per_region*pages_per_unit
        if page_size!=PAGE or not region_pages or physical_pages<2 or physical_pages>4096:continue
        if page+physical_pages>len(mm)//STRIDE:continue
        region=None if address==0xffffffff else address//(PAGE*region_pages)
        groups[(serial,total_units,region_pages)].append({'page':page,'region':region,'sequence':seq,'erase_count':erase_count,'physical_pages':physical_pages,'logical_pages':pages_per_unit})
    return groups

def mappings(mm,headers,region_pages):
    records=[];free=defaultdict(list)
    for h in headers:
        if h['region'] is None:continue
        for index in range(1,h['physical_pages']):
            page=h['page']+index;off=page*STRIDE
            raw=mm[off:off+STRIDE]
            if raw==b'\xff'*STRIDE:
                free[h['region']].append(page);continue
            local=decode_tag(raw[PAGE:])
            if local is None or local>=region_pages:continue
            records.append({'page':page,'sector':h['region']*region_pages+local,'local':local,'sequence':h['sequence']})
    latest={}
    for r in sorted(records,key=lambda r:(r['sequence'],r['page'])):latest[r['sector']]=r
    return latest,free

def bpb(mm,latest):
    if 0 not in latest:return None
    off=latest[0]['page']*STRIDE;boot=mm[off:off+PAGE]
    if boot[510:512]!=b'\x55\xaa':return None
    size=struct.unpack_from('<H',boot,11)[0]
    sectors=struct.unpack_from('<H',boot,19)[0] or struct.unpack_from('<I',boot,32)[0]
    kind=boot[54:62].decode('ascii',errors='replace').strip()
    if kind not in ('FAT12','FAT16'):kind=boot[82:90].decode('ascii',errors='replace').strip()
    if size!=PAGE or not sectors or sectors*size>512*1024*1024 or kind not in ('FAT12','FAT16','FAT32'):return None
    return {'bytes_per_sector':size,'sectors':sectors,'bytes':size*sectors,'kind':kind}

def extract(mm,latest,sectors):
    result=bytearray(PAGE*sectors)
    for sector,r in latest.items():
        if sector<sectors:result[sector*PAGE:(sector+1)*PAGE]=mm[r['page']*STRIDE:r['page']*STRIDE+PAGE]
    return result

def occupied_sectors(fat):
    """Include zero-filled file sectors: unmapped VBF reads are not zero reads.

    A zero-filled logical reconstruction can hide missing physical allocations.
    In particular SQLite freelist pages may be entirely zero and must still be
    programmed when their FAT cluster is allocated.
    """
    sector_size=struct.unpack_from('<H',fat,11)[0]
    cluster_sectors=fat[13]
    reserved=struct.unpack_from('<H',fat,14)[0]
    copies=fat[16]
    roots=struct.unpack_from('<H',fat,17)[0]
    total=struct.unpack_from('<H',fat,19)[0] or struct.unpack_from('<I',fat,32)[0]
    fat_sectors=struct.unpack_from('<H',fat,22)[0] or struct.unpack_from('<I',fat,36)[0]
    root_sectors=(roots*32+sector_size-1)//sector_size
    data_start=reserved+copies*fat_sectors+root_sectors
    if sector_size!=PAGE or not cluster_sectors or data_start>=total:
        raise ValueError('invalid FAT geometry while discovering occupied sectors')
    clusters=(total-data_start)//cluster_sectors
    kind=12 if clusters<4085 else 16 if clusters<65525 else 32
    table=fat[reserved*PAGE:(reserved+fat_sectors)*PAGE]
    used=set(range(data_start))
    for cluster in range(2,clusters+2):
        if kind==12:
            offset=cluster+cluster//2
            entry=struct.unpack_from('<H',table,offset)[0]
            value=(entry>>4 if cluster&1 else entry)&0xfff
        elif kind==16:
            value=struct.unpack_from('<H',table,cluster*2)[0]
        else:
            value=struct.unpack_from('<I',table,cluster*4)[0]&0x0fffffff
        if value:
            first=data_start+(cluster-2)*cluster_sectors
            used.update(range(first,min(first+cluster_sectors,total)))
    return used

def hashes(root):
    result={}
    for p in sorted(root.rglob('*')):
        if p.is_symlink():raise ValueError('symlink payloads unsupported')
        if p.is_file():
            name=str(p.relative_to(root)).replace('\\','/').casefold()
            if name in result:raise ValueError('case-colliding FAT filenames')
            result[name]={'name':str(p.relative_to(root)),'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
    return result

def directories(root):
    result={}
    for path in sorted(root.rglob('*')):
        if path.is_symlink():raise ValueError('symlink payloads unsupported')
        if path.is_dir():
            name=str(path.relative_to(root)).replace('\\','/').casefold()
            if name in result:raise ValueError('case-colliding FAT directories')
            result[name]=str(path.relative_to(root))
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input',type=Path,required=True)
    p.add_argument('--output',type=Path)
    p.add_argument('--source',type=Path)
    p.add_argument('--list',action='store_true')
    select=p.add_mutually_exclusive_group()
    select.add_argument('--base-page',type=int)
    select.add_argument('--serial',type=lambda x:int(x,0))
    p.add_argument('--report',type=Path)
    args=p.parse_args()
    with args.input.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as mm:
        groups=discover(mm);volumes=[]
        for key,headers in groups.items():
            latest,free=mappings(mm,headers,key[2]);fs=bpb(mm,latest)
            volumes.append({'serial':hex(key[0]),'total_units':key[1],'region_pages':key[2],'base_page':min(h['page'] for h in headers),'native_header_count':len(headers),'physical_pages_per_unit':sorted({h['physical_pages'] for h in headers}),'logical_pages_per_unit':sorted({h['logical_pages'] for h in headers}),'filesystem':fs,'free_data_pages':sum(map(len,free.values()))})
        if args.list:
            print(json.dumps(volumes,indent=2));return
        if args.output is None or args.source is None:p.error('--output and --source required for injection')
        if args.output.exists():p.error('output must not exist')
        if args.input.resolve()==args.output.resolve():p.error('input and output must differ')
        chosen=[v for v in volumes if v['filesystem'] and ((args.serial is not None and int(v['serial'],16)==args.serial) or (args.base_page is not None and v['base_page']==args.base_page))]
        if len(chosen)!=1:p.error('select exactly one formatted volume with --serial or --base-page; use --list')
        volume=chosen[0];key=(int(volume['serial'],16),volume['total_units'],volume['region_pages']);headers=groups[key]
        latest,free=mappings(mm,headers,key[2]);original=extract(mm,latest,volume['filesystem']['sectors'])
        native_headers={h['page']:mm[h['page']*STRIDE:h['page']*STRIDE+STRIDE] for h in headers}
    if not args.source.is_dir():p.error('source must be a directory')
    manifest=hashes(args.source);expected_dirs=directories(args.source)
    if set(manifest)&set(expected_dirs):p.error('case-colliding file and directory paths')
    children=sorted(args.source.iterdir())
    with tempfile.TemporaryDirectory(prefix='smeg-vbf-volume-') as temp:
        fat=Path(temp)/'volume.fat';fat.write_bytes(original)
        if children:run(['mcopy','-s','-o','-i',str(fat)]+[str(c) for c in children]+['::/'])
        updated=fat.read_bytes()
        if len(updated)!=len(original):raise ValueError('filesystem unexpectedly resized')
        occupied=occupied_sectors(updated)
        required_allocations=occupied-set(latest)
        changes=[s for s in range(volume['filesystem']['sectors']) if s in required_allocations or original[s*PAGE:(s+1)*PAGE]!=updated[s*PAGE:(s+1)*PAGE]]
        plan=[]
        for sector in changes:
            if sector in latest:
                plan.append({'sector':sector,'page':latest[sector]['page'],'operation':'replace_existing_main_data'})
            else:
                region=sector//key[2]
                if not free[region]:raise ValueError('insufficient native free pages in region'+str(region))
                plan.append({'sector':sector,'page':free[region].pop(0),'operation':'append_allocation','local':sector%key[2]})
        args.output.parent.mkdir(parents=True,exist_ok=True)
        subprocess.run(['cp','--reflink=auto',str(args.input),str(args.output)],check=True)
        # A protected baseline can be read-only; only its new experiment copy
        # needs owner-write permission for injection and subsequent QEMU I/O.
        args.output.chmod(args.output.stat().st_mode | stat.S_IWUSR)
        with args.output.open('r+b') as f,mmap.mmap(f.fileno(),0) as mm:
            for r in plan:
                offset=r['page']*STRIDE
                if r['operation']=='append_allocation':
                    if mm[offset:offset+STRIDE]!=b'\xff'*STRIDE:raise ValueError('new allocation page not erased')
                    mm[offset+PAGE:offset+STRIDE]=tag_oob(r['local'])
                mm[offset:offset+PAGE]=updated[r['sector']*PAGE:(r['sector']+1)*PAGE]
            for page,raw in native_headers.items():
                if mm[page*STRIDE:page*STRIDE+STRIDE]!=raw:raise ValueError('native VBF header changed')
            verification,_=mappings(mm,headers,key[2])
            if occupied-set(verification):
                raise ValueError('occupied FAT sectors lack physical VBF allocations')
            readback=extract(mm,verification,volume['filesystem']['sectors'])
            if readback!=updated:raise ValueError('VBF sector readback mismatch')
            mm.flush()
        fat.write_bytes(readback);check=Path(temp)/'readback';check.mkdir()
        if children:run(['mcopy','-s','-i',str(fat),'::/*',str(check)])
        actual=hashes(check)
        for name,expected in manifest.items():
            if name not in actual or expected['sha256']!=actual[name]['sha256']:raise ValueError('file readback mismatch:'+name)
        actual_dirs=directories(check)
        for name in expected_dirs:
            if name not in actual_dirs:raise ValueError('directory readback mismatch:'+name)
        listing=run(['mdir','-i',str(fat),'::/'],text=True).stdout
        report={'input':str(args.input),'output':str(args.output),'volume':volume,'payload_root':str(args.source),'payload_files':list(manifest.values()),'payload_directories':list(expected_dirs.values()),'file_readback_sha256_matches':len(manifest),'directory_readback_matches':len(expected_dirs),'changed_sectors':len(plan),'new_allocations':sum(r['operation']=='append_allocation' for r in plan),'occupied_sectors_physically_allocated':len(occupied),'previously_unmapped_occupied_sectors':len(required_allocations),'native_headers_preserved':True,'fat_sha256':hashlib.sha256(updated).hexdigest(),'native_mount_validation':'pending','listing':listing}
        destination=args.report or args.output.with_suffix(args.output.suffix+'.json');destination.write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps({'output':str(args.output),'files_verified':len(manifest),'directories_verified':len(expected_dirs),'changed_sectors':len(plan),'report':str(destination)}))
if __name__=='__main__':main()
