#!/usr/bin/env python3
"""Native SMEG5.43 gzip-SQLite .inf metadata (offline sandbox only).

Evidence: BSP InitCrc002875cc/ComputeCrc002875dc; tables00728678/00728778;
CheckCRCInf00294560 skips first4 ASCII bytes when checksumming metadata.
NAV sqlite3_gzUnixVFS close path0106d91c..0106da00 formats
'%02x%02x\nCRC_UNCOMPRESSED:%02x%02x\nUSIZE:%ld\nSIZE:%ld':
compressedCRC arguments are both zero, USIZE is logical raw size, SIZE is
zero on successful close. It prepends4 metadata-CRC hex bytes, no final LF.
No CRC32, no signed-decimal checksum, no compressed-byte checksum field here.
Raw/unwrapped DB sidecar generation is deliberately unsupported: unchanged
factory raw DBs have no native sidecar fixture; use the recovered gzip form.
"""
from functools import lru_cache
import argparse
import gzip
import hashlib
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
KERNEL = ROOT/'artifacts/phase2/package/SMEG_PLUS_UPG/BSP/SMEG_PLUS_512/vxWorks.bin'
TABLE_OFFSET = 0x728678-0x200000
TABLE_SHA256 = '0f7e0467164156c1a7df335b4d0d3a829e20210dd91dddf23b937f63ac9e78ea'

@lru_cache(maxsize=1)
def _tables():
    with KERNEL.open('rb') as stream:
        stream.seek(TABLE_OFFSET)
        tables = stream.read(512)
    if hashlib.sha256(tables).hexdigest() != TABLE_SHA256:
        raise ValueError('Original SMEG5.43 native CRC table bytes do not match')
    return tables[:256], tables[256:]

def crc16(data: bytes) -> int:
    """Return native printed-order16-bit CRC; exact recovered table algorithm."""
    t0,t1 = _tables()
    a=c=0
    for byte in data:
        index=byte^c
        c,a=t0[index]^a,t1[index]
    return (c<<8)|a

def encode_inf(raw: bytes, stored: bytes, gzip_wrapped: bool = True) -> bytes:
    """Encode the recovered native gzip VFS sidecar, validating stored content."""
    if not gzip_wrapped:
        raise ValueError('Only the recovered gzip SQLite sidecar format is supported')
    if not stored.startswith(b'\x1f\x8b') or gzip.decompress(stored)!=raw:
        raise ValueError('Stored gzip content does not decode to the supplied raw DB')
    if len(raw)>0x7fffffff:
        raise ValueError('USIZE exceeds native signed32-bit long range')
    body=f'0000\nCRC_UNCOMPRESSED:{crc16(raw):04x}\nUSIZE:{len(raw)}\nSIZE:0'.encode('ascii')
    return f'{crc16(body):04x}'.encode('ascii')+body

def parse_inf(inf: bytes) -> dict:
    match=re.fullmatch(rb'([0-9a-fA-F]{4})([0-9a-fA-F]{4})\nCRC_UNCOMPRESSED:([0-9a-fA-F]{4})\nUSIZE:([0-9]+)\nSIZE:([0-9]+)',inf)
    if not match:
        raise ValueError('Invalid native gzip SQLite .inf grammar')
    header,compressed,uncompressed,usize,size=match.groups()
    result={'metadata_crc':int(header,16),'compressed_crc':int(compressed,16),
            'raw_crc':int(uncompressed,16),'usize':int(usize),'size':int(size)}
    if crc16(inf[4:])!=result['metadata_crc']:
        raise ValueError('Metadata CRC mismatch')
    return result

def verify_inf(raw: bytes, stored: bytes, inf: bytes) -> bool:
    parsed=parse_inf(inf)
    if parsed['compressed_crc'] or parsed['size']:
        raise ValueError('Nonzero compressedCRC/SIZE is outside recovered gzip VFS format')
    if parsed['usize']!=len(raw) or parsed['raw_crc']!=crc16(raw):
        raise ValueError('Raw database size/CRC mismatch')
    if not stored.startswith(b'\x1f\x8b') or gzip.decompress(stored)!=raw:
        raise ValueError('Stored gzip bytes differ from raw DB')
    return True

def self_test() -> None:
    """Compare exact sidecar bytes emitted by the original running guest."""
    path=ROOT/'artifacts/phase4/previous-emulator/USER_DATA/sqlite/up_common.sqlite'
    stored=path.read_bytes();raw=gzip.decompress(stored)
    inf=Path(str(path)+'.inf').read_bytes()
    assert len(raw)==33792 and len(stored)==7804
    assert crc16(raw)==0xd48e and crc16(inf[4:])==0x9c31
    assert encode_inf(raw,stored,True)==inf and verify_inf(raw,stored,inf)
    for bad in (inf+b'\n',inf[:4]+b'1000'+inf[8:],inf[:25]+b'0'+inf[26:]):
        try:
            verify_inf(raw,stored,bad)
        except ValueError:
            pass
        else:
            raise AssertionError('Corrupt metadata accepted')
    for size in (1,100,4096):
        raw=bytes((index*37)&255 for index in range(size))
        stored=gzip.compress(raw,mtime=0)
        assert verify_inf(raw,stored,encode_inf(raw,stored,True))
    print('Exact native fixture, gzip round trips and corrupt metadata rejection passed')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('stored',type=Path,nargs='?',help='Existing gzip SQLite file')
    p.add_argument('--output',type=Path,help='Write sidecar here; otherwise verify stored.inf')
    p.add_argument('--self-test',action='store_true')
    a=p.parse_args()
    if a.self_test:
        self_test()
    else:
        if a.stored is None:
            p.error('stored file is required unless --self-test is selected')
        stored=a.stored.read_bytes();raw=gzip.decompress(stored)
        if a.output:
            inf=encode_inf(raw,stored,gzip_wrapped=True)
            verify_inf(raw,stored,inf);a.output.write_bytes(inf)
        else:
            verify_inf(raw,stored,Path(str(a.stored)+'.inf').read_bytes())
        print(f'Native gzip SQLite metadata verified: raw={len(raw)}, stored={len(stored)}, CRC={crc16(raw):04x}')
