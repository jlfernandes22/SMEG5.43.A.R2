#!/usr/bin/env python3
"""Offline guard tests only: never starts QEMU or opens a physical device."""
from pathlib import Path
import tempfile
import unittest

import test_stock_restore_cold_boot as cold


class StockColdGuards(unittest.TestCase):
    def fixture(self):
        source = cold.PHASE / 'stock-restore/offline-test.raw'
        sha = 'ab' * 32
        audit = {'nand': str(source), 'nand_sha256': sha,
                 'all_seven_database_contents_verified': True,
                 'all_three_raw_container_bytes_verified': True,
                 'stored_candidate_bytes_and_databases_verified': True,
                 'raw_containers': [], 'databases': []}
        for path, source_sha in cold.STOCK.items():
            audit['raw_containers'].append({'path': path, 'source_sha256': source_sha,
                'expected_stored_sha256': 'cd' * 32,
                'matches': [{'sha256': 'cd' * 32, 'exact_payload_match': True}]})
        for name in cold.DATABASES:
            audit['databases'].append({'name': name, 'present': True, 'native_INF_valid': True,
                'sqlite_integrity': 'ok', 'expected_database_contents_match': True,
                'expected_source': str(cold.BACKUP / name)})
        return audit, source, sha

    def test_complete_original_audit(self):
        cold.validate_audit(*self.fixture())

    def test_every_global_completion_field_is_required(self):
        for name in ('all_seven_database_contents_verified', 'all_three_raw_container_bytes_verified',
                     'stored_candidate_bytes_and_databases_verified'):
            audit, source, sha = self.fixture()
            audit[name] = False
            with self.subTest(name=name), self.assertRaises(ValueError):
                cold.validate_audit(audit, source, sha)

    def test_missing_or_stale_nand_hash(self):
        for value in (None, '00' * 32):
            audit, source, sha = self.fixture()
            audit['nand_sha256'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                cold.validate_audit(audit, source, sha)

    def test_wrong_nand_path(self):
        audit, source, sha = self.fixture()
        audit['nand'] += '.different'
        with self.assertRaises(ValueError):
            cold.validate_audit(audit, source, sha)

    def test_modified_application_and_missing_raw_match(self):
        for mutation in ('source', 'match'):
            audit, source, sha = self.fixture()
            if mutation == 'source':
                audit['raw_containers'][0]['source_sha256'] = 'ee' * 32
            else:
                audit['raw_containers'][0]['matches'][0]['exact_payload_match'] = False
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                cold.validate_audit(audit, source, sha)

    def test_modified_or_missing_database_and_invalid_inf(self):
        for mutation in ('source', 'count', 'inf'):
            audit, source, sha = self.fixture()
            if mutation == 'source':
                audit['databases'][0]['expected_source'] = str(cold.PHASE / 'modified.sqlite')
            elif mutation == 'count':
                audit['databases'].pop()
            else:
                audit['databases'][0]['native_INF_valid'] = False
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                cold.validate_audit(audit, source, sha)

    def test_hmp_parser(self):
        self.assertEqual(cold.parse_hmp_word('000000000227f7b4: 0x409e0010\r\n'), 0x409e0010)
        with self.assertRaises(ValueError):
            cold.parse_hmp_word('Cannot access memory')

    def defined_fixture(self):
        audit, source, sha = self.fixture()
        audit['all_three_raw_container_bytes_verified'] = False
        audit['stored_candidate_bytes_and_databases_verified'] = False
        audit['all_three_raw_container_defined_regions_verified'] = True
        audit['stored_defined_payload_regions_and_databases_verified'] = True
        item = audit['raw_containers'][1]
        match = item['matches'][0]
        match['exact_payload_match'] = False
        match['native_defined_regions_match'] = True
        regions = {'padding': {'offset': 168, 'length': 1880, 'indeterminate': True}}
        for name, target in cold.expected_harmony_regions(item['path']).items():
            regions[name] = {'offset': target['offset'], 'length': target['length'],
                             'actual_sha256': target['sha256'], 'expected_sha256': target['sha256']}
        match['native_defined_regions'] = regions
        return audit, source, sha

    def test_native_defined_region_audit_without_false_fullbyte_claim(self):
        cold.validate_audit(*self.defined_fixture())

    def test_inconsistent_fullbyte_claim_rejected(self):
        audit, source, sha = self.defined_fixture()
        audit['all_three_raw_container_bytes_verified'] = True
        with self.assertRaises(ValueError):
            cold.validate_audit(audit, source, sha)

    def test_defined_region_corruption_and_inexact_app_rejected(self):
        for mutation in ('metadata_hash', 'body_hash', 'body_offset', 'padding_scope', 'application'):
            audit, source, sha = self.defined_fixture()
            regions = audit['raw_containers'][1]['matches'][0]['native_defined_regions']
            if mutation == 'metadata_hash':
                regions['metadata']['actual_sha256'] = 'ee' * 32
            elif mutation == 'body_hash':
                regions['body']['actual_sha256'] = 'ee' * 32
            elif mutation == 'body_offset':
                regions['body']['offset'] = 2050
            elif mutation == 'padding_scope':
                regions['padding']['length'] = 1900
            else:
                audit['raw_containers'][0]['matches'][0]['exact_payload_match'] = False
                audit['raw_containers'][0]['matches'][0]['native_defined_regions_match'] = True
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                cold.validate_audit(audit, source, sha)

    def test_original_source_fingerprints(self):
        for path, expected in cold.SOURCE_HASHES.items():
            with self.subTest(path=path):
                self.assertEqual(cold.digest(path), expected)

    def test_regular_guard_rejects_symlink_and_outside_file(self):
        with tempfile.TemporaryDirectory(dir=cold.PHASE, prefix='cold-guard-test-') as tmp:
            file = Path(tmp) / 'ordinary'; file.write_bytes(b'offline test')
            self.assertEqual(cold.regular_phase14(file), file.resolve())
            link = Path(tmp) / 'link'; link.symlink_to(file)
            with self.assertRaises(ValueError):
                cold.regular_phase14(link)
            with self.assertRaises(ValueError):
                cold.regular_phase14(Path(__file__))


if __name__ == '__main__':
    unittest.main()
