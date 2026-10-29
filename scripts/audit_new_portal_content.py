#!/usr/bin/env python3
"""Verify a stopped QEMU local-app installation preserves all stock SYSTEM files."""
import argparse,hashlib,json,mmap,os,subprocess,tempfile
from pathlib import Path
from inject_volume import discover,mappings,bpb,extract
from audit_warmlight_single_flag import no_visible_writer,read_snapshot

ROOT=Path(__file__).resolve().parents[1]
def sha(p):
    with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()

def system_files(nand,work,label):
    with nand.open('rb')as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)as mm:
        found=[(k,h)for k,h in discover(mm).items()if min(x['page']for x in h)==59072]
        assert len(found)==1;k,h=found[0];latest,_=mappings(mm,h,k[2]);fs=bpb(mm,latest)
        fat=work/(label+'.fat');fat.write_bytes(extract(mm,latest,fs['sectors']))
    folder=work/label;folder.mkdir()
    subprocess.run(['mcopy','-s','-i',str(fat),'::/*',str(folder)],check=True,capture_output=True,env=dict(os.environ,MTOOLS_SKIP_CHECK='1'))
    return {str(p.relative_to(folder)):dict(bytes=p.stat().st_size,sha256=sha(p))for p in folder.rglob('*')if p.is_file()}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--before',type=Path,required=True);p.add_argument('--after',type=Path,required=True);p.add_argument('--html',type=Path);p.add_argument('--theme-previews',action='store_true');p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    assert a.theme_previews != bool(a.html)
    assert not a.output.exists()
    for f in (a.before,a.after,*([a.html]if a.html else [])):
        assert f.resolve().is_relative_to(ROOT/'artifacts') and f.is_file() and not f.is_symlink()
    no_visible_writer(a.before);no_visible_writer(a.after)
    with tempfile.TemporaryDirectory()as td:
        work=Path(td);before=system_files(a.before,work,'before');after=system_files(a.after,work,'after')
        changed=[n for n,v in before.items()if after.get(n)!=v];added=sorted(set(after)-set(before))
        assert not changed
        if a.theme_previews:
            from prepare_all_theme_assets import previews
            expected={f'Data_Base/BOARDFS/GUI_STYLE/GUIS_RESSOURCES/Harmony{uid}/skin.jpg':hashlib.sha256(previews(g,'AUDIO')[uid][1]).hexdigest()
                      for g,uid in [(1,1),(1,2),(1,3),(2,4),(2,7),(2,8)]}
            # Native DOSFS is case-insensitive and retains original directory
            # casing (Data_base/boardfs); compare path identity accordingly.
            actual_lower={n.casefold():after[n]for n in added}
            assert set(actual_lower)=={n.casefold()for n in expected}
            assert all(actual_lower[n.casefold()]['sha256']==v for n,v in expected.items())
        else:
            assert added==['internet_default/customfuel/index.html']
            assert after[added[0]]['sha256']==sha(a.html)
        snap=read_snapshot(a.after,work,'app',observe=True)
        assert snap['containers'][0]['full_native_payload_exact']
        if not a.theme_previews:assert all(c['full_native_payload_exact']for c in snap['containers'])
        assert all(d['sqlite_integrity_and_INF_valid']for d in snap['databases'].values())
        rows=snap['databases']['up_config.sqlite']['rows']['UP_Keys']['rows']
        portal=[r['StringValue']for r in rows if (r['Section'],r['Name'],r['Idx'])==('internet','URL_PSA_portal',0)]
        assert portal==(['/SYSTEM/internet_default/portal/index.html']if a.theme_previews else['/SYSTEM/internet_default/customfuel/index.html'])
    report=dict(physical_device_access=False,before=str(a.before),after=str(a.after),original_SYSTEM_files_byte_exact=len(before),
        changed_original_files=changed,added_SYSTEM_files={n:after[n]for n in added},all_three_stock_binary_and_theme_containers_byte_exact=True,
        all_seven_databases_valid=True,persisted_portal=portal[0],native_UI_screenshot_required_separately=True)
    report['all_three_stock_binary_and_theme_containers_byte_exact']=not a.theme_previews
    report['original_application_binary_byte_exact']=True
    a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))

if __name__=='__main__':main()
