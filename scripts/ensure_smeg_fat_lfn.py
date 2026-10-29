#!/usr/bin/env python3
"""Ensure a native SMEG USER_DATA payload has the literal lowercase sqlite LFN.

Regular virtual FAT32 image files under artifacts/phase13 only. A real device,
symlink, existing wrong LFN chain, or non-adjacent insertion is refused. The
only mutation is insertion of one LFN record and movement of its own unchanged
short entry into the following free record. No FAT or file contents change.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import struct

ROOT = Path(__file__).resolve().parents[1]
ALLOWED = (ROOT / 'artifacts/phase13').resolve()
PARTS = ['SMEG_PLUS_UPG', 'NAV', 'USER_DATA', 'user_data', 'sqlite']


def lfn_checksum(short):
    value = 0
    for byte in short:
        value = (((value & 1) << 7) | (value >> 1)) + byte
        value &= 255
    return value


def lfn_record(name, short):
    units = name.encode('utf-16le') + b'\0\0'
    assert len(units) <= 26
    units += b'\xff' * (26 - len(units))
    record = bytearray(32)
    record[0], record[11], record[13] = 0x41, 15, lfn_checksum(short)
    record[1:11], record[14:26], record[28:32] = units[:10], units[10:22], units[22:26]
    return bytes(record)


class Fat32:
    def __init__(self, stream, length):
        self.stream, self.length = stream, length
        mbr = self.read(0, 512)
        assert mbr[510:] == b'\x55\xaa'
        candidates = []
        for index in range(4):
            record = mbr[446 + index * 16:462 + index * 16]
            first, sectors = struct.unpack_from('<II', record, 8)
            if record[4] in (0x0b, 0x0c):
                candidates.append((first * 512, sectors * 512))
        assert len(candidates) == 1, 'Expected exactly one MBR FAT32 partition'
        self.partition, self.partition_bytes = candidates[0]
        assert self.partition > 0 and self.partition + self.partition_bytes <= length
        boot = self.read(self.partition, 512)
        assert boot[510:] == b'\x55\xaa'
        self.bps = struct.unpack_from('<H', boot, 11)[0]
        self.spc, reserved, self.fats = boot[13], struct.unpack_from('<H', boot, 14)[0], boot[16]
        self.fat_sectors = struct.unpack_from('<I', boot, 36)[0]
        self.root = struct.unpack_from('<I', boot, 44)[0]
        assert self.bps == 512 and self.spc and self.spc & (self.spc - 1) == 0
        assert struct.unpack_from('<HH', boot, 17) == (0, 0), 'Expected FAT32 root format'
        assert struct.unpack_from('<H', boot, 22)[0] == 0 and self.fat_sectors > 0
        self.cluster_bytes = self.bps * self.spc
        self.fat = self.partition + reserved * self.bps
        self.data = self.fat + self.fats * self.fat_sectors * self.bps
        self.max_cluster = (self.partition + self.partition_bytes - self.data) // self.cluster_bytes + 1

    def read(self, offset, length):
        assert 0 <= offset <= self.length and 0 <= length <= self.length - offset
        self.stream.seek(offset)
        result = self.stream.read(length)
        assert len(result) == length
        return result

    def clusters(self, cluster):
        seen = set()
        while cluster < 0x0ffffff8:
            assert 2 <= cluster <= self.max_cluster and cluster not in seen
            assert len(seen) < 1_000_000
            seen.add(cluster)
            yield cluster
            cluster = struct.unpack('<I', self.read(self.fat + 4 * cluster, 4))[0] & 0x0fffffff

    def slots(self, cluster):
        for current in self.clusters(cluster):
            base = self.data + (current - 2) * self.cluster_bytes
            for offset in range(0, self.cluster_bytes, 32):
                absolute = base + offset
                yield absolute, self.read(absolute, 32)

    def entries(self, cluster):
        pending = []
        for offset, record in self.slots(cluster):
            if record[0] == 0:
                break
            if record[0] == 0xe5:
                pending = []
                continue
            if record[11] == 15:
                pending.append((offset, record))
                continue
            short = record[:8].decode('ascii').rstrip()
            ext = record[8:11].decode('ascii').rstrip()
            name = None
            if pending:
                expected = len(pending)
                assert pending[0][1][0] == 0x40 | expected
                assert all(r[0] == expected - index | (0x40 if index == 0 else 0)
                           and r[13] == lfn_checksum(record[:11]) and r[12] == 0 and r[26:28] == b'\0\0'
                           for index, (_, r) in enumerate(pending)), 'Invalid LFN sequence/checksum'
                units = b''.join(r[1:11] + r[14:26] + r[28:32] for _, r in reversed(pending))
                name = units.decode('utf-16le').split('\0')[0].rstrip('\uffff')
            yield {'offset': offset, 'short': short + ('.' + ext if ext else ''),
                   'lfn': name, 'lfn_offsets': [o for o, _ in pending], 'nt': record[12],
                   'attr': record[11], 'cluster': struct.unpack_from('<H', record, 26)[0] |
                   struct.unpack_from('<H', record, 20)[0] << 16,
                   'bytes': struct.unpack_from('<I', record, 28)[0], 'raw_hex': record.hex()}
            pending = []

    def target(self):
        cluster, chain = self.root, []
        for component in PARTS:
            matches = [entry for entry in self.entries(cluster) if entry['attr'] & 16 and
                       (entry['lfn'] or entry['short']).casefold() == component.casefold()]
            assert len(matches) == 1, f'Missing or ambiguous directory {component!r}'
            parent = cluster
            entry = matches[0]
            chain.append(entry)
            cluster = entry['cluster']
        return parent, entry, chain

    def payload_hashes(self, cluster):
        result = {}
        for entry in self.entries(cluster):
            if entry['short'] in ('.', '..'):
                continue
            assert not entry['attr'] & 16, 'Only direct SQLite payload files expected'
            name = entry['lfn'] or entry['short']
            remaining, digest = entry['bytes'], hashlib.sha256()
            assert remaining <= 64 * 1024 * 1024
            if remaining:
                for current in self.clusters(entry['cluster']):
                    take = min(remaining, self.cluster_bytes)
                    digest.update(self.read(self.data + (current - 2) * self.cluster_bytes, take))
                    remaining -= take
                    if not remaining:
                        break
            assert remaining == 0
            result[name] = {'bytes': entry['bytes'], 'sha256': digest.hexdigest()}
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    if args.apply and args.check:
        parser.error('Choose --apply or --check')
    if args.image.is_symlink():
        parser.error('Symlink image refused')
    image = args.image.resolve()
    if not image.is_relative_to(ALLOWED) or not stat.S_ISREG(image.stat().st_mode):
        parser.error('Regular phase13 image required; block devices are refused')
    if args.report:
        report_path = args.report.resolve()
        if not report_path.is_relative_to(ALLOWED) or report_path.exists():
            parser.error('Report must be a new path inside artifacts/phase13')
    with image.open('r+b' if args.apply else 'rb') as stream:
        volume = Fat32(stream, image.stat().st_size)
        parent, target, chain = volume.target()
        before_payload = volume.payload_hashes(target['cluster'])
        protected = {name: entry for entry in volume.entries(parent)
                     if (name := entry['lfn'] or entry['short']) != (target['lfn'] or target['short'])}
        report = {'image': str(image), 'physical_devices_accessed': False,
                  'applied': False, 'before': chain, 'payload_hashes_before': before_payload,
                  'edits': [], 'already_correct': target['lfn'] == 'sqlite'}
        if target['lfn'] != 'sqlite':
            raw = bytes.fromhex(target['raw_hex'])
            lfn = lfn_record('sqlite', raw[:11])
            if target['lfn_offsets']:
                assert len(target['lfn_offsets']) == 1, 'Refusing multi-record LFN rewrite'
                edits = [(target['lfn_offsets'][0], lfn)]
            else:
                slots = list(volume.slots(parent))
                position = next(i for i, (offset, _) in enumerate(slots) if offset == target['offset'])
                assert position + 2 < len(slots), 'Need adjacent free slots; no allocation attempted'
                next_offset, next_raw = slots[position + 1]
                assert next_raw[0] in (0, 0xe5), 'Next directory record is occupied; refusing relocation of unrelated entries'
                edits = [(target['offset'], lfn), (next_offset, raw)]
                if next_raw[0] == 0 and slots[position + 2][1][0] != 0:
                    offset, end_raw = slots[position + 2]
                    edits.append((offset, b'\0' + end_raw[1:]))
            report['edits'] = [{'offset': offset, 'before_hex': volume.read(offset, 32).hex(),
                                'after_hex': replacement.hex()} for offset, replacement in edits]
            if args.apply:
                for offset, replacement in edits:
                    stream.seek(offset)
                    assert stream.write(replacement) == 32
                stream.flush()
                os.fsync(stream.fileno())
                report['applied'] = True
        _, updated, after_chain = volume.target()
        after_payload = volume.payload_hashes(updated['cluster'])
        remaining = {entry['lfn'] or entry['short']: entry for entry in volume.entries(parent)
                     if entry['cluster'] != updated['cluster']}
        assert protected == remaining, 'Unrelated directory entries changed'
        assert before_payload == after_payload
        assert image.stat().st_size == volume.length
        report.update(after=after_chain, payload_hashes_after=after_payload,
                      payload_unchanged=True, unrelated_entries_unchanged=True,
                      verified=updated['lfn'] == 'sqlite')
        if args.apply:
            assert report['verified']
        if args.report:
            report_path.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))
        if args.check and not report['verified']:
            raise SystemExit(2)


if __name__ == '__main__':
    main()
