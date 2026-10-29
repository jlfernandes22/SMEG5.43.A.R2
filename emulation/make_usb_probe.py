#!/usr/bin/env python3
"""Build a regular-file-only FAT32/MBR USB probe; never access physical drives."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
OFFSET = 2048 * 512
SIZE = 128 * 1024 * 1024


def run(*args):
    return subprocess.run(args, check=True, capture_output=True,
                          env=dict(os.environ, MTOOLS_SKIP_CHECK='1'))


def build(output, mode):
    output = output.resolve()
    if output.exists() or str(output).startswith('/dev/'):
        raise ValueError('New regular image path required')
    output.parent.mkdir(parents=True, exist_ok=True)
    files = {'README.txt': f'SMEG QEMU ONLY: {mode}\r\nNo car configuration changes.\r\n'.encode()}
    if mode == 'scripts':
        files.update({
            'autorun.inf': b'[autorun]\r\nopen=probe.vxs\r\naction=SMEG harmless marker\r\n',
            'probe.vxs': b'printf("SMEG_USB_PROBE_VXS_EXECUTED\\n")\n',
            'autorun.sh': b'#!/bin/sh\necho SMEG_USB_PROBE_SH_EXECUTED\n',
            'startup.cmd': b'printf("SMEG_USB_PROBE_CMD_EXECUTED\\n")\n',
            'startupScript': b'printf("SMEG_USB_PROBE_STARTUP_EXECUTED\\n")\n',
        })
    if mode == 'native':
        sys.path.insert(0, str(ROOT/'scripts'))
        from smeg_db_inf import crc16
        payload=(ROOT/'artifacts/phase5/usb/native-marker/probe.out').read_bytes()
        body=(f'{crc16(payload):04x}\r\nVER:SMEG5.43.A.R2\r\nTYPE:RELOCABLE\r\nID:0\r\nCOMPRESSED:NO\r\nSIZE:{len(payload)}\r\nENTRY:YES\r\n').encode()
        files['FLYING/probe.out']=payload
        files['FLYING/probe.out.inf']=f'{crc16(body):04x}'.encode()+body
        body=b'0000\r\nACTION:TemporaryBootRom\r\nLOAD_AND_EXECUTE:/bd0/FLYING/probe.out\r\n'
        files['FLYING/doctor_smeg_plus_i.inf']=f'{crc16(body):04x}'.encode()+body
    if mode == 'doctor':
        files['FLYING/doctor_smeg_plus_i.inf'] = b'SMEG_QEMU_ONLY_EXISTENCE_MARKER\n'
    if mode == 'update':
        files.update({
            'SMEG_PLUS_UPG/README.txt': b'Incomplete inert update-detection probe; not a firmware package.\n',
            'SMEG_PLUS_UPG/UpgPlugin.out': b'SMEG_USB_PROBE_NOT_AN_ELF_MODULE\n',
            'SMEG_PLUS_UPG/upgrade.cmd': b'printf("SMEG_USB_PROBE_UPGRADE_CMD_EXECUTED\\n")\n',
        })
    with tempfile.TemporaryDirectory(prefix='smeg-usb-probe-') as tmp:
        tmp = Path(tmp)
        partition = tmp / 'partition.raw'
        with partition.open('xb') as f:
            f.truncate(SIZE)
        run('mkfs.vfat', '-F', '32', '-n', 'SMEG_PROBE', str(partition))
        mbr = bytearray(512)
        # One FAT32 LBA partition; start/length are expressed in 512-byte sectors.
        mbr[446:462] = struct.pack('<B3sB3sII', 0, b'\xfe\xff\xff', 0x0c,
                                   b'\xfe\xff\xff', 2048, SIZE // 512)
        mbr[510:512] = b'\x55\xaa'
        with output.open('xb') as f, partition.open('rb') as src:
            f.write(mbr); f.seek(OFFSET)
            while chunk := src.read(1024 * 1024):
                f.write(chunk)
        image = str(output) + '@@' + str(OFFSET)
        for directory in sorted({str(Path(name).parent) for name in files} - {'.'}):
            run('mmd', '-i', image, '::/' + directory)
        manifest = []
        for i, (name, content) in enumerate(files.items()):
            source = tmp / f'file-{i}'
            source.write_bytes(content)
            run('mcopy', '-i', image, str(source), '::/' + name)
            readback = tmp / f'readback-{i}'
            run('mcopy', '-i', image, '::/' + name, str(readback))
            assert readback.read_bytes() == content
            manifest.append({'path': '/' + name, 'sha256': hashlib.sha256(content).hexdigest()})
        # Known generated media is a positive control for the native media indexer.
        source_media = ROOT / 'artifacts/phase4/media-test.raw'
        positive = tmp / 'Positive.mp3'
        run('mcopy', '-i', str(source_media), '::/Bench.mp3', str(positive))
        run('mcopy', '-i', image, str(positive), '::/Positive.mp3')
        manifest.append({'path':'/Positive.mp3', 'sha256':hashlib.sha256(positive.read_bytes()).hexdigest()})
    result = {'mode':mode, 'physical_device_access':False, 'format':'MBR/FAT32',
              'partition_offset_bytes':OFFSET, 'partition_bytes':SIZE, 'files':manifest}
    output.with_suffix('.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--mode', choices=['baseline', 'scripts', 'update', 'doctor', 'native'], required=True)
    a = p.parse_args()
    build(a.output, a.mode)
