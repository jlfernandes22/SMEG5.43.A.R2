#!/usr/bin/env python3
"""Configuration and missing-identity tests; no hardware access."""
from contextlib import redirect_stderr
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import backup_theme_readonly_return as backup
import local_device_config as config
import probe_live_car as probe
import stage_backup_only_usb as stage


class LocalDeviceConfig(unittest.TestCase):
    def load(self, payload=None, environment=None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / '.smeg-local.json'
            if payload is not None:
                path.write_text(payload)
            with patch.object(config, 'LOCAL_CONFIG', path),\
                 patch.dict(config.os.environ, environment or {}, clear=True):
                return config.load_local_device_config()

    def test_missing_file_has_no_device_defaults(self):
        self.assertEqual(self.load(), {})

    def test_local_identity_and_environment_precedence(self):
        settings = {'usb_serial': 'TEST_SERIAL', 'usb_model': 'TEST_MODEL',
                    'usb_capacity_bytes': 4096, 'usb_mount': '/mnt/test-usb',
                    'usb_device': '/dev/disk/by-id/usb-TEST_DEVICE',
                    'bluetooth_address': '02:00:00:00:00:01'}
        actual = self.load(json.dumps(settings), {'SMEG_USB_SERIAL': 'OVERRIDE_SERIAL',
                                                 'SMEG_USB_CAPACITY_BYTES': '8192'})
        self.assertEqual(actual, dict(settings, usb_serial='OVERRIDE_SERIAL', usb_capacity_bytes=8192))

    def test_invalid_capacity_and_structure_rejected_without_values(self):
        for capacity in [0, -1, True, 'PRIVATE_INVALID_CAPACITY']:
            with self.subTest(capacity=capacity), self.assertRaisesRegex(ValueError, 'positive byte count') as error:
                self.load(json.dumps({'usb_capacity_bytes': capacity}))
            self.assertNotIn('PRIVATE_INVALID_CAPACITY', str(error.exception))
        for payload in ['[]', '{PRIVATE_INVALID_JSON']:
            with self.subTest(payload=payload), self.assertRaises(ValueError) as error:
                self.load(payload)
            self.assertNotIn('PRIVATE_INVALID_JSON', str(error.exception))

    def test_empty_or_nontext_identity_rejected(self):
        for identity in ['', ' ', 123]:
            with self.subTest(identity=identity), self.assertRaisesRegex(ValueError, 'nonempty string'):
                self.load(json.dumps({'usb_serial': identity}))


class UnconfiguredEntryPoints(unittest.TestCase):
    def test_backup_fails_before_device_inventory(self):
        with patch.multiple(backup, SERIAL='', DEVICE='', MOUNT=None),\
             patch.object(sys, 'argv', ['backup', '--output', '/tmp/test-output']),\
             patch.object(backup.subprocess, 'check_output') as inventory,\
             redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            backup.main()
        self.assertEqual(error.exception.code, 2)
        inventory.assert_not_called()

    def test_stage_fails_before_device_inventory(self):
        with patch.object(stage, 'load_local_device_config', return_value={}),\
             patch.object(sys, 'argv', ['stage', '--mount', '/mnt/test-usb']),\
             patch.object(stage.subprocess, 'check_output') as inventory,\
             self.assertRaisesRegex(RuntimeError, 'Configure an explicit USB identity'):
            stage.main()
        inventory.assert_not_called()

    def test_probe_requires_explicit_peer_before_host_inventory(self):
        with patch.object(probe, 'load_local_device_config', return_value={}),\
             patch.object(sys, 'argv', ['probe']),\
             patch.object(probe, 'run') as inventory,\
             redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            probe.main()
        self.assertEqual(error.exception.code, 2)
        inventory.assert_not_called()


if __name__ == '__main__':
    unittest.main()
