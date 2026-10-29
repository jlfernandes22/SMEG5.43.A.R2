#!/usr/bin/env python3
"""Prepare only the explicitly authorized experimental WARMLIGHT USB test.

Never opens a car interface. Replaces the known Verbatim's old, fully backed-up
v7 filesystem with the exact small USB image exercised by the stock emulator.
This does not certify physical operation or exact native runtime-row purity.
"""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path

from prepare_verified_theme_usb import (
    DEVICE, SERIAL, ROOT, device_state, require, validate_open_device,
    validate_open_source,
)

BASE = ROOT / 'artifacts/phase17/warmlight-only'
IMAGE = BASE / 'usb-probe/usb.raw'
IMAGE_BYTES = 135266304
IMAGE_SHA = '8b23dc13340418d8f13443e99bbf727022b042e9ddac1893ce73d35460d86459'
OLD_IMAGE = ROOT / 'artifacts/phase15/candidate-allthemes-v7/usb.raw'
OLD_BYTES = 2147483648
OLD_SHA = '22f088123679b4755d506c9b27b58cbac7ee005879bf3ff6d06a7f948f398ee8'
RECEIPT = BASE / 'physical-usb-preparation.json'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify_prefix(fd, size, expected):
    os.lseek(fd, 0, os.SEEK_SET)
    h = hashlib.sha256()
    left = size
    while left:
        chunk = os.read(fd, min(left, 8 << 20))
        require(chunk, 'Truncated USB prefix')
        h.update(chunk)
        left -= len(chunk)
    require(h.hexdigest() == expected, 'USB prefix differs; preserve and inspect before any write')
    return h.hexdigest()


def replace_prefix(fd, source, size, expected):
    os.lseek(fd, 0, os.SEEK_SET)
    source.seek(0)
    h = hashlib.sha256()
    copied = 0
    while copied < size:
        chunk = source.read(min(size - copied, 8 << 20))
        require(chunk, 'Source truncated during preparation')
        h.update(chunk)
        view = memoryview(chunk)
        while view:
            written = os.write(fd, view)
            require(written > 0, 'Short USB write')
            view = view[written:]
        copied += len(chunk)
    require(not source.read(1), 'Source grew during preparation')
    require(h.hexdigest() == expected, 'Source changed during preparation; USB not ready')
    os.fsync(fd)
    fcntl.ioctl(fd, 0x1261)  # BLKFLSBUF, before independent block readback.
    return verify_prefix(fd, size, expected)


def validate_proofs():
    proof = json.loads((BASE / 'test-results.json').read_text())
    request = proof['requested_native_API_change']
    require(request == {'database': 'up_config.sqlite', 'table': 'UP_Keys',
                        'Section': 'display', 'Name': 'Harm_11', 'Idx': 0,
                        'IntValue': [0, 1]}, 'Unexpected native request')
    require(proof['result'] == 'WARMLIGHT_stock_emulator_USB_single_requested_flag_native_UI_and_USB_free_cold_boot_PASS',
            'Missing matching stock-runtime proof')
    require(proof['all_three_stock_application_and_theme_containers_byte_exact']
            and proof['all_seven_original_SQLite_integrity_INF_and_schemas_valid']
            and proof['original_stock_source_unchanged'], 'Stock proof failed')
    require(not proof['strict_all_database_rows_except_target_preserved'],
            'Preserve the recorded runtime-state caveat; do not silently replace evidence')
    for item in proof['evidence']:
        p = Path(item['path'])
        require(p.is_relative_to(ROOT) and not p.is_symlink() and p.is_file(), 'Unsafe evidence path')
        require(digest(p) == item['sha256'], 'Bound evidence changed: ' + str(p))
    metadata = json.loads((BASE / 'usb-probe/usb.json').read_text())
    require({x['path'] for x in metadata['files']} == {
        'FLYING/warmlight_enable.out', 'FLYING/warmlight_enable.out.inf',
        'FLYING/doctor_smeg_plus_i.inf'}, 'Unexpected payload members')
    require(metadata['image_sha256'] == IMAGE_SHA, 'Wrong tested USB image')
    require(not IMAGE.is_symlink() and not OLD_IMAGE.is_symlink(), 'Image symlinks refused')
    require(OLD_IMAGE.stat().st_size == OLD_BYTES and digest(OLD_IMAGE) == OLD_SHA,
            'Original broad-update image must be preserved and verified on host first')
    return proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    validate_proofs()
    device, mounted = device_state()
    report = {'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'scope': 'User-authorized experimental physical USB preparation only',
              'USB_serial': SERIAL, 'device': str(DEVICE), 'resolved_device': device['path'],
              'image': str(IMAGE), 'image_sha256': IMAGE_SHA, 'image_bytes': IMAGE_BYTES,
              'old_contents_backed_up_as': str(OLD_IMAGE), 'old_image_sha256': OLD_SHA,
              'physical_car_accessed': False, 'physical_operation_verified': False,
              'strict_native_runtime_row_purity_verified': False,
              'only_requested_parameter': 'display.Harm_11[0] = true',
              'firmware_or_theme_resource_payload': False, 'USB_written': False,
              'mounted': mounted}
    if not args.write:
        print(json.dumps(report, indent=2))
        return
    require(os.geteuid() == 0, 'Administrator authentication required')
    require(not RECEIPT.exists(), 'Do not overwrite a physical preparation receipt')
    require(not mounted, 'Unmount the identified USB first')
    with os.fdopen(os.open(IMAGE, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as source:
        validate_open_source(source, IMAGE_SHA, IMAGE_BYTES)
        device, mounted = device_state()
        require(not mounted, 'USB became mounted')
        fd = os.open(DEVICE, os.O_RDWR | os.O_EXCL)
        try:
            validate_open_device(fd, device)
            print('Checking existing USB against preserved v7 image before writing', flush=True)
            report['old_USB_prefix_sha256'] = verify_prefix(fd, OLD_BYTES, OLD_SHA)
            print('Writing and reading back the exact WARMLIGHT-only test image', flush=True)
            report['new_USB_prefix_sha256'] = replace_prefix(fd, source, IMAGE_BYTES, IMAGE_SHA)
            report['readback_verified'] = True
            report['USB_written'] = True
            fcntl.ioctl(fd, 0x125f)  # BLKRRPART.
        finally:
            os.close(fd)
    RECEIPT.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
