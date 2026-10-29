#!/usr/bin/env python3
"""Artifact-only radio header and ESSENTIEL icon compatibility experiment."""
import copy
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zlib

from inspect_internet_harmony import ROOT, PAGE, SLOT_SIZE, bank
from prepare_all_theme_assets import parse_candidate, seal_inf
from prepare_essentiel_color_style import parse, encode
from prepare_theme_menu_dependencies_experiment import pool, add_images

SOURCE = ROOT/'artifacts/phase15/theme-assets/all-eight-menu-colour-style-v7'
OUTPUT = ROOT/'artifacts/phase15/theme-assets/all-eight-layout-v8'

def sha(data): return hashlib.sha256(data).hexdigest()
def props(node): return {c['tag']: c for c in node['children'] if not c['children']}
def group(node): return next(c for c in node['children'] if c['tag'] == 86)
def locate(raw, key):
    count, base = struct.unpack_from('>II', raw, 4)
    found = [(i, base+struct.unpack_from('>I',raw,0x6c+i*16+8)[0])
             for i in range(count) if struct.unpack_from('>II',raw,0x6c+i*16)==key]
    assert len(found)==1
    i, start = found[0]
    tree,end=parse(raw,start)
    assert encode(tree)==raw[start:end]
    return i,tree,raw[start:end]

def append(raw,key,tree):
    i,_,old=locate(raw,key)
    new=encode(tree); offset=(len(raw)+15)&~15
    result=bytearray(raw+b'\0'*(offset-len(raw))+new)
    base=struct.unpack_from('>I',raw,8)[0]
    struct.pack_into('>I',result,0,len(result))
    struct.pack_into('>I',result,0x6c+i*16+8,offset-base)
    assert locate(result,key)[2]==new
    return bytes(result),dict(window=list(key),old_sha256=sha(old),new_sha256=sha(new))

def adjust_radio(raw,name):
    changes=[]
    # Shift only the header controls, leaving tuner buttons, RDS and the
    # application-wide clock/temperature at their original coordinates.
    for screen in (14,15):
        _,tree,_=locate(raw,(3,screen)); widgets=group(tree)['children']; moved=0
        props(tree)[20]['value']=0
        def shift(node):
            nonlocal moved
            p=props(node)
            if 57 not in p:
                node['children'].insert(2,dict(tag=57,kind=0,value=48,children=[]))
            else:p[57]['value']+=48
            moved+=1
        if name=='ELLIPTIC':
            # Native group at origin owns the frequency, memory and FM tile.
            candidates=[n for n in widgets if props(n).get(87,{}).get('value')==1
                        and props(n).get(28,{}).get('value')==1 and 56 not in props(n)]
            assert len(candidates)==1
            for n in group(candidates[0])['children']:
                p=props(n); y=p.get(57,{}).get('value',0)
                if y<=156:shift(n)
        else:
            for n in widgets:
                p=props(n)
                if p.get(57,{}).get('value')==21 and p.get(56,{}).get('value') in (5,697):shift(n)
                if p.get(56,{}).get('value') in (83,84) and p.get(87,{}).get('value') in (613,614):
                    for c in group(n)['children']:
                        cp=props(c)
                        if 57 in cp and cp[57]['value']<156:shift(c)
        assert moved>5
        raw,audit=append(raw,(3,screen),tree);audit['header_widgets_shifted_48px']=moved;changes.append(audit)
    return raw,changes

def add_colour_icon(raw):
    donor=zlib.decompress(bank(4)[2][0]['_payload'][4:])
    _,dt,_=locate(donor,(22,0)); _,tree,_=locate(raw,(22,0))
    def colours(node):
        found=[]
        if node['tag']==85 and props(node).get(76,{}).get('value')==1583:found.append(node)
        for c in node['children']:found+=colours(c)
        return found
    source=colours(dt)[0]; targets=colours(tree)
    icon=copy.deepcopy(next(c for c in source['children']if c['tag']==54))
    oldpool=pool(raw,21); images,mapping,_=add_images(oldpool,pool(donor,21),{524,525})
    def remap(node):
        if node['tag']==33:node['value']=mapping[node['value']]
        for c in node['children']:remap(c)
    remap(icon)
    target=next(n for n in targets if props(n).get(87,{}).get('value')==194)
    assert not any(c['tag']==54 for c in target['children'])
    target['children'].append(icon)
    oldoffset=struct.unpack_from('>I',raw,22*4)[0]; oldend=oldoffset+len(oldpool)
    delta=len(images)-len(oldpool)
    result=bytearray(raw[:oldoffset]+images+raw[oldend:])
    struct.pack_into('>II',result,21*4,len(images),oldoffset)
    count,base=struct.unpack_from('>II',raw,4)
    for i in range(count):
        field=0x6c+i*16+8;relative=struct.unpack_from('>I',raw,field)[0]
        if base+relative>=oldend:struct.pack_into('>I',result,field,relative+delta)
    struct.pack_into('>I',result,0,len(result))
    result,audit=append(bytes(result),(22,0),tree)
    audit['private_icon_image_ID_map']=mapping
    return result,[audit]

def main():
    global OUTPUT
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,default=OUTPUT);a=p.parse_args()
    OUTPUT=a.output.resolve();assert OUTPUT.is_relative_to(ROOT/'artifacts/phase15/theme-assets')
    assert not OUTPUT.exists(); manifest=json.loads((SOURCE/'manifest.json').read_text())
    OUTPUT.mkdir(parents=True);revised=copy.deepcopy(manifest);changes=[]
    for item in manifest['files']:
        data=(SOURCE/'overlay'/item['path']).read_bytes()
        assert len(data)==item['bytes'] and sha(data)==item['SHA256']
        target=OUTPUT/'overlay'/item['path'];target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
    for b in revised['banks']:
        target=OUTPUT/'overlay/HARMONY'/f"BigHarmony_{b['target_group']}/BIG_HARMONY.bin"
        old=target.read_bytes();result=bytearray(old[:PAGE*2]);cursor=2
        for i,e in enumerate(b['entries']):
            record=bytearray(old[2084+i*216:2084+(i+1)*216]);page,size,crc=struct.unpack_from('>III',record,204)
            payload=old[page*PAGE:page*PAGE+size];assert zlib.crc32(payload)==crc
            name=e['theme']
            if name in ('ELLIPTIC','CUBIC','ESSENTIEL'):
                raw=zlib.decompress(payload[4:]);modified,audit=add_colour_icon(raw) if name=='ESSENTIEL'else adjust_radio(raw,name)
                payload=struct.pack('>I',len(modified))+zlib.compress(modified,9)
                changes.append(dict(theme=name,windows=audit))
                e.update(compressed_SHA256=sha(payload),expanded_SHA256=sha(modified))
            struct.pack_into('>III',record,204,cursor,len(payload),zlib.crc32(payload))
            result[2084+i*216:2084+(i+1)*216]=record
            result.extend(payload+b'\xff'*(-len(payload)%PAGE));cursor+=((len(payload)+PAGE-1)//PAGE)
        result=bytes(result);hs=36+216*len(b['entries']);assert len(result)<=SLOT_SIZE
        parse_candidate(result,hs);target.write_bytes(result)
        inf=Path(str(target)+'.inf');hcrc=zlib.crc32(result[PAGE:PAGE+hs])
        inf.write_bytes(seal_inf(inf.read_bytes(),result,{'HEADER_CRC32':struct.unpack('>i',struct.pack('>I',hcrc))[0]}))
        b.update(bytes=len(result),SHA256=sha(result),spare_bytes=SLOT_SIZE-len(result),header_CRC32=f'{hcrc:08x}')
    revised.update(layout_fixes=changes,physical_car_approved=False,runtime_verified=False)
    revised['files']=[dict(path=str(p.relative_to(OUTPUT/'overlay')),bytes=p.stat().st_size,SHA256=sha(p.read_bytes()))
                      for p in sorted((OUTPUT/'overlay').rglob('*'))if p.is_file()]
    (OUTPUT/'manifest.json').write_text(json.dumps(revised,indent=2)+'\n')
    print(json.dumps(dict(output=str(OUTPUT),changes=changes),indent=2))

if __name__=='__main__':main()
