"""Explicit peer selection and CLI rejection tests; no controller access."""
import argparse
from pathlib import Path
import subprocess
import sys
import unittest

from hci_peer import bluetooth_peer, peer_bytes

ROOT = Path(__file__).resolve().parent


class ExplicitPeerTests(unittest.TestCase):
    def test_normalization_and_HCI_byte_order(self):
        # Deliberately synthetic, locally administered fixture addresses.
        self.assertEqual(bluetooth_peer('02:ab:cd:00:00:01'), '02:AB:CD:00:00:01')
        self.assertEqual(peer_bytes('02:AB:CD:00:00:01'), b'\x01\x00\x00\xcd\xab\x02')
        self.assertEqual(peer_bytes('02:00:00:00:00:02'), b'\x02\x00\x00\x00\x00\x02')

    def test_invalid_peer_is_rejected_without_echoing_value(self):
        for value in ('PRIVATE_INVALID_PEER', '02:00:00:00:00', '02:00:00:00:00:01:02',
                      ' 02:00:00:00:00:01', '02:00:00:00:00:GG'):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError) as error:
                peer_bytes(value)
            self.assertNotIn(value, str(error.exception))

    def rejected(self, script, *args):
        result = subprocess.run([sys.executable, str(ROOT / script), *args],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('--peer', result.stderr)

    def test_missing_peer_fails_before_UI_or_radio_setup(self):
        self.rejected('drive_hci_pairing.py', '--name', 'Synthetic Phone')
        self.rejected('hci_radio_diagnostic.py', '--radio-fd', '-1', '--output', '/unused-output')
        self.rejected('hci_radio_lease.py', '--mode', 'diagnostic')
        self.rejected('hci_radio_lease.py', '--mode', 'infineon-live', '--reuse-host-bond')

    def test_invalid_peer_fails_before_UI_or_radio_setup(self):
        for script in ('drive_hci_pairing.py', 'hci_radio_diagnostic.py', 'hci_radio_lease.py'):
            with self.subTest(script=script):
                self.rejected(script, '--peer', 'PRIVATE_INVALID_PEER')


if __name__ == '__main__':
    unittest.main()
