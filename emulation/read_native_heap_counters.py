#!/usr/bin/env python3
"""Read BSP256 heap counters while an existing private test VM is paused.

No guest calls, memory writes, stop/resume, or physical-device access. These
are native system-heap counters, not a measurement of every guest/GPU pool.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
from run_usb_probe import QMP

ROOT = Path(__file__).resolve().parents[1]
KERNEL = ROOT / 'artifacts/phase2/package/SMEG_PLUS_UPG/BSP/SMEG_PLUS_256/vxWorks.bin'
KERNEL_SHA = 'e8aff17981ae5ba8c1574fba70ed747d32ae08badec932bfae38b7f6a4694110'


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--runtime', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    runtime = a.runtime.resolve()
    output = a.output.resolve()
    if (not any(runtime.is_relative_to(ROOT / 'artifacts' / phase)
                for phase in ('phase15', 'phase16'))
            or a.runtime.is_symlink() or not runtime.is_file()
            or not output.is_relative_to(ROOT / 'artifacts/phase16')
            or output.exists() or a.output.is_symlink()):
        p.error('Existing regular private-test runtime and new Phase16 output required')
    state = json.loads(runtime.read_text())
    if (state.get('ram_mib', state.get('RAM_MiB')) != 256
            or state.get('physical_devices_accessed') is not False
            or state.get('USB_attached') is not False
            or not re.fullmatch(r'/tmp/smeg-p(?:15|16)-[A-Za-z0-9]+', state.get('prefix', ''))):
        p.error('Only the existing private256MiB noUSB test runtime is supported')
    if sha(KERNEL) != KERNEL_SHA:
        p.error('BSP256 source fingerprint mismatch')
    # memPartInfoGet: e0/e8/100 word counts are shifted left once into
    # MEM_PART_STATS fields at0/0xc/0x14. dc/e4 copy block counts directly.
    kb = KERNEL.read_bytes()
    expected = {0x49BE84: '817f00e0', 0x49BE8C: '556b083c',
                0x49BE94: '815f00dc', 0x49BEBC: '819f00e8',
                0x49BECC: '817f00e4', 0x49BED4: '815f0100'}
    for address, opcode in expected.items():
        if kb[address - 0x200000:address - 0x200000 + 4].hex() != opcode:
            p.error('Native allocator layout precondition failed')
    q = QMP(state['prefix'] + '.qmp')
    try:
        status = q.call('query-status')
        if status.get('running') is not False or status.get('status') != 'paused':
            p.error('Caller must already own a paused VM checkpoint')

        def read_words(address, count):
            response = q.call('human-monitor-command', {
                'command-line': f'xp /{count}wx {address:#x}'})
            words = [int(x, 16) for x in re.findall(r'0x([0-9a-fA-F]{8})\b', response)]
            if len(words) != count:
                raise ValueError('Unexpected monitor memory response')
            return words

        part = read_words(0x865C70, 1)[0]  # memSysPartId in the BSP256 symbol map.
        if not 0x200000 <= part < 0x10000000 - 0x104 or part % 4:
            raise ValueError('Invalid native system partition pointer')
        words = read_words(part + 0xDC, 10)
        free, allocated, peak = words[1] * 2, words[3] * 2, words[9] * 2
        if not 0 < free + allocated <= 256 * 1024 * 1024 or not allocated <= peak <= 256 * 1024 * 1024:
            raise ValueError('Inconsistent native counter sample')
        if q.call('query-status').get('status') != 'paused':
            raise ValueError('VM changed state during checkpoint')
    finally:
        q.close()
    report = {
        'scope': 'Passive paused-VM native system-heap counter sample; no guest calls or writes',
        'runtime': str(runtime.relative_to(ROOT)), 'runtime_sha256': sha(runtime),
        'kernel_source_sha256': KERNEL_SHA, 'native_memPartInfoGet': '0x49be40',
        'memSysPartId_address': '0x865c70', 'partition_pointer': hex(part),
        'partition_words_dc_through_100': [hex(x) for x in words],
        'free_bytes': free, 'free_blocks': words[0],
        'allocated_bytes': allocated, 'allocated_blocks': words[2],
        'peak_allocated_bytes_since_boot': peak,
        'sample_may_interrupt_allocator_transaction': True,
        'private_guest_pools_and_host_GLES_memory_not_accounted_separately': True,
        'physical_RAM_or_GPU_measurement': False,
        'VM_stopped_or_resumed_by_tool': False,
        'guest_memory_or_instruction_writes': False,
        'physical_devices_accessed': False,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'report': str(output.relative_to(ROOT)), 'free_bytes': free,
                      'peak_allocated_bytes_since_boot': peak}))


if __name__ == '__main__':
    main()
