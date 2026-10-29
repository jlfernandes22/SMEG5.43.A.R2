#!/usr/bin/env python3
"""Stage the user-authorized, read-only theme diagnostic on the pinned USB.

Preserves the old files and full overwritten prefix before any device write.
This is media preparation, not a claim of physical-car execution or success.
"""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path

from prepare_verified_theme_usb import (
    DEVICE, SERIAL, ROOT, require, device_state, validate_open_device,
    validate_open_source,
)
from prepare_warmlight_test_usb import verify_prefix, replace_prefix

BASE = ROOT / 'artifacts/phase19/theme-inventory'
IMAGE = BASE / 'usb-probe/usb.raw'
SIZE = 135266304
SHA = 'f16708f0e6720c73f7d07ffc544dffe143c132d097fa4f0841fea5ae34f0c46b'
BACKUP = BASE / 'physical-before'
RECEIPT = BASE / 'physical-usb-preparation.json'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def proofs():
    metadata = json.loads((BASE / 'usb-probe/usb.json').read_text())
    require(metadata['image_sha256'] == SHA and metadata['no_configuration_requests']
            and metadata['no_firmware_or_theme_resources'], 'Unexpected payload')
    require({r['path'] for r in metadata['files']} == {
        'FLYING/theme_inventory.out', 'FLYING/theme_inventory.out.inf',
        'FLYING/doctor_smeg_plus_i.inf'}, 'Unexpected USB members')
    runtime = json.loads((BASE / 'runtime-verification.json').read_text())
    require(runtime['inventory_success']
            and runtime['all_seven_pre_export_to_post_inventory_SQL_databases_unchanged']
            and runtime['all_three_stock_app_and_theme_containers_byte_exact']
            and not runtime['configuration_or_flash_writer_called_by_helper'],
            'Read-only runtime proof failed')
    result = json.loads((ROOT / 'artifacts/phase8/usb-maintenance/runs/T19INVENTORY01/result.json').read_text())
    require(result['wait_marker_seen'] and result['returncode'] == 0, 'Native test incomplete')
    manifest = json.loads((BACKUP / 'copy-manifest.json').read_text())
    require(manifest['USB_serial'] == SERIAL and manifest['read_only_mount']
            and len(manifest['files']) >= 21, 'Original USB backup incomplete')
    for row in manifest['files']:
        path = BACKUP / 'files' / row['path']
        require(path.is_relative_to(BACKUP / 'files') and not path.is_symlink()
                and path.stat().st_size == row['bytes'] and digest(path) == row['sha256'],
                'USB file backup mismatch')
    return metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    metadata = proofs()
    device, mounted = device_state()
    report = dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  USB_serial=SERIAL, resolved_device=device['path'], image=str(IMAGE),
                  image_sha256=SHA, image_bytes=SIZE, payload_files=metadata['files'],
                  user_authorization='Prepare read-only theme inventory USB',
                  physical_car_accessed=False, physical_car_execution_verified=False,
                  requested_configuration_changes=[], USB_written=False)
    require(not IMAGE.is_symlink(), 'Source symlink refused')
    with os.fdopen(os.open(IMAGE, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as source:
        validate_open_source(source, SHA, SIZE)
        if not args.write:
            print(json.dumps(report, indent=2))
            return
        require(os.geteuid() == 0, 'Administrator authentication required')
        require(not RECEIPT.exists(), 'Preparation receipt already exists')
        require(not mounted, 'USB must be unmounted')
        device, mounted = device_state()
        require(not mounted, 'USB became mounted')
        fd = os.open(DEVICE, os.O_RDWR | os.O_EXCL)
        try:
            validate_open_device(fd, device)
            old = BACKUP / 'original-prefix.raw'
            h = hashlib.sha256()
            left = SIZE
            with old.open('xb') as saved:
                while left:
                    chunk = os.read(fd, min(left, 8 << 20))
                    require(chunk, 'Truncated original USB')
                    saved.write(chunk)
                    h.update(chunk)
                    left -= len(chunk)
                saved.flush()
                os.fsync(saved.fileno())
            require(old.stat().st_size == SIZE and digest(old) == h.hexdigest(),
                    'Original USB prefix backup failed')
            report['original_prefix_backup'] = str(old)
            report['original_prefix_sha256'] = verify_prefix(fd, SIZE, h.hexdigest())
            report['readback_sha256'] = replace_prefix(fd, source, SIZE, SHA)
            report.update(USB_written=True, readback_verified=True)
            fcntl.ioctl(fd, 0x125f)
        finally:
            os.close(fd)
    RECEIPT.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
