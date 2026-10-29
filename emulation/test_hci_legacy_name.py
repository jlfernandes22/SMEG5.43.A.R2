import unittest
from hci_bridge import complete
from hci_legacy_name import LegacyNameRequest, ENCRYPT_OFF, ENCRYPT_ON, AUTH_ON

REQUEST = bytes.fromhex('0119040a5e4ef14d222201000000')
STATUS = bytes.fromhex('040f0400011904')
NAME = bytes.fromhex('040711005e4ef14d2222') + b'OnePlus 12'

class LegacyNameTests(unittest.TestCase):
    def configured(self):
        model = LegacyNameRequest()
        self.assertEqual(model.guest(ENCRYPT_ON), [ENCRYPT_ON])
        model.radio(complete(0x0c22))
        return model

    def test_restore_before_completion_and_deferred_connection(self):
        model = self.configured()
        self.assertEqual(model.guest(REQUEST), [ENCRYPT_OFF])
        self.assertEqual(model.radio(complete(0x0c22)), ([], [REQUEST]))
        self.assertEqual(model.radio(STATUS), ([STATUS], []))
        # A guest connection cannot escape while encryption is suspended.
        connect = bytes.fromhex('01050400')
        self.assertEqual(model.guest(connect), [])
        self.assertEqual(model.radio(NAME), ([], [ENCRYPT_ON]))
        self.assertEqual(model.radio(complete(0x0c22)), ([NAME], [AUTH_ON]))
        self.assertEqual(model.radio(complete(0x0c20)), ([], [connect]))
        self.assertTrue(model.connection_seen)
        self.assertEqual(model.encryption_mode, 1)
        self.assertEqual(model.state, 'idle')

    def test_scan_and_connection_guards(self):
        model = self.configured()
        model.guest(bytes.fromhex('011a0c0103'))
        model.radio(complete(0x0c1a))
        self.assertEqual(model.guest(REQUEST), [REQUEST])
        model.guest(bytes.fromhex('011a0c0100'))
        model.radio(complete(0x0c1a))
        model.guest(bytes.fromhex('01050400'))
        model.radio(complete(0x0c20))
        self.assertEqual(model.guest(REQUEST), [REQUEST])

    def test_failed_policy_change_does_not_invent_success(self):
        model = self.configured()
        model.guest(REQUEST)
        self.assertEqual(model.radio(complete(0x0c22, b'\x12')), ([], [REQUEST]))
        error = bytes.fromhex('040f040c011904')
        self.assertEqual(model.radio(error), ([error], []))

    def test_failed_lookup_restores_before_forwarding_real_error(self):
        model = self.configured()
        model.guest(REQUEST)
        model.radio(complete(0x0c22))
        error = bytes.fromhex('040f0404011904')
        self.assertEqual(model.radio(error), ([], [ENCRYPT_ON]))
        self.assertEqual(model.radio(complete(0x0c22)), ([error], []))

    def test_failed_restore_and_unexpected_link_close_the_bridge(self):
        model = self.configured()
        model.guest(REQUEST)
        model.radio(complete(0x0c22))
        model.radio(NAME)
        with self.assertRaises(RuntimeError):
            model.radio(complete(0x0c22, b'\x12'))
        model = self.configured()
        model.guest(REQUEST)
        with self.assertRaises(RuntimeError):
            model.radio(bytes.fromhex('0201000000'))

    def test_timeout_closes_bridge_and_reset_restores_initial_state(self):
        model = self.configured()
        model.guest(REQUEST)
        model.deadline = 0
        with self.assertRaises(TimeoutError):
            model.tick()
        model = self.configured()
        model.radio(complete(0x0c03))
        self.assertEqual(model.encryption_mode, 0)
        self.assertEqual(model.guest(REQUEST), [REQUEST])

    def test_authentication_first_keeps_global_encryption_enabled(self):
        model = self.configured()
        connect = bytes.fromhex('01050400')
        self.assertEqual(model.guest(connect), [AUTH_ON])
        self.assertEqual(model.encryption_mode, 1)
        self.assertEqual(model.radio(complete(0x0c20)), ([], [connect]))
        physical_status = bytes.fromhex('040f0400010504')
        self.assertEqual(model.radio(physical_status), ([physical_status], []))

    def test_authentication_failure_does_not_fabricate_connection(self):
        model = self.configured()
        connect = bytes.fromhex('01050400')
        model.guest(connect)
        self.assertEqual(model.radio(complete(0x0c20,b'\x12')), ([], [connect]))
        physical_error = bytes.fromhex('040f040c010504')
        self.assertEqual(model.radio(physical_error), ([physical_error], []))

if __name__ == '__main__':
    unittest.main()
