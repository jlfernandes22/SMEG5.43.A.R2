#!/usr/bin/env python3
"""Prepare an independent coherent 256/256 NAND seed; never starts QEMU.

Native updater must establish its FlashFX and filesystems. This is not a
conversion of any existing 512-MiB NAND and not physical-unit RAM evidence.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
KERNEL = ROOT/'artifacts/phase2/package/SMEG_PLUS_UPG/BSP/SMEG_PLUS_256/vxWorks.bin'
EXPECTED = 'e8aff17981ae5ba8c1574fba70ed747d32ae08badec932bfae38b7f6a4694110'

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    out = a.output.resolve()
    if not out.is_relative_to(ROOT/'artifacts') or out.exists() or out.with_suffix('.json').exists():
        p.error('Output and sidecar must be new workspace artifacts')
    kernel = KERNEL.read_bytes()
    assert hashlib.sha256(kernel).hexdigest() == EXPECTED
    # Original BSP256 device-configuration data; raw Audio slots end exactly
    # at the reserved-bottom boundary. Leave native installer to build disks.
    config = struct.unpack_from('>4I', kernel, 0x74340c-0x200000)
    assert config == (0x40000000, 0x1c400, 0x200, 0x80000)
    assert 0x4f60000 + 0x21a0000 == config[1]*1024 == 0x7100000
    assert struct.unpack_from('>2I', kernel, 0x79ff38-0x200000+16) == (0x10000000,)*2
    subprocess.run([sys.executable, str(ROOT/'emulation/make_flash.py'),
                    '--variant','256','--size-mib','256','--application','AUDIO_BT_256',
                    '--output',str(out)], cwd=ROOT, check=True, capture_output=True, text=True)
    assert out.stat().st_size == 276824064
    report = {
        'scope':'Independent bootstrap-only native256/256 test seed; no VM started',
        'kernel_SHA256':EXPECTED, 'NAND':str(out), 'bytes':out.stat().st_size,
        'native_board_index':4, 'RAM_MiB':256, 'NAND_data_MiB':256,
        'native_FlashFX_config_address':'0x74340c',
        'native_FlashFX_config_words':[hex(v) for v in config],
        'reserved_bottom_bytes':config[1]*1024, 'reserved_top_bytes':config[2]*1024,
        'managed_upper_bound_before_BBM_bytes':256*1024*1024-(config[1]+config[2])*1024,
        'raw_Audio_slot_end':'0x7100000',
        'raw_theme_banks_fit':True, 'native_full_install_fit_verified':False,
        'note':'Managed-space arithmetic is not proof all extracted files fit; native updater result and file/hash audits required.',
        'next_command_template':[
            sys.executable,'emulation/test_usb_maintenance.py','--seed',str(out),
            '--usb','<NEW_VIRTUAL_USB_IMAGE_CONTAINING_EXACT_CANDIDATE>',
            '--tag','ALL256NATIVE','--ram-mib','256','--audio-256',
            '--boot-seconds','150','--post-insert-seconds','600'],
        'required_acceptance':[
            'Corrected model chooses descriptor4 MB810 INTEGRE RAM256/Flash256; no high-stack unmapped accesses',
            'Native updater installs exact USB candidate and all DB/files audit against original payload',
            'Stock two-theme coherent256 baseline before eight-theme memory comparisons',
            'All eight selection/coldboot outcomes and actual native free/peak memory recorded'],
        'VM_started':False, 'physical_devices_accessed':False,
    }
    out.with_suffix('.memory-test.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))

if __name__ == '__main__':
    main()
