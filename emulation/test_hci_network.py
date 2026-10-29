import unittest
from analyze_hci_network import analyze


def acl(direction, cid, payload, fragment=False):
    data = len(payload).to_bytes(2, 'little') + cid.to_bytes(2, 'little') + payload
    def row(chunk, flag):
        packet = b'\x02' + (0x33 | flag << 12).to_bytes(2, 'little') + len(chunk).to_bytes(2, 'little') + chunk
        return {'event':'packet', 'direction':direction, 'hex':packet.hex()}
    if fragment:
        return [row(data[:31], 2), row(data[31:], 1)]
    return [row(data, 2)]


def session(fragment=False, ack=5):
    rows = [{'event':'listening'}]
    rows += acl('guest', 1, bytes.fromhex('020104000f004000'))
    rows += acl('radio', 1, bytes.fromhex('030108006000400000000000'))
    bootp = bytearray(240)
    bootp[0] = 2
    bootp[16:20] = bytes([10,19,241,96])
    bootp[236:240] = bytes.fromhex('63825363')
    bootp += bytes([53,1,ack,54,4,10,19,241,172,255])
    ip = bytearray(20); ip[0] = 0x45; ip[9] = 17
    udp = bytes.fromhex('00430044') + (8 + len(bootp)).to_bytes(2,'big') + b'\0\0'
    return rows + acl('radio', 0x40, b'\x02\x08\x00' + ip + udp + bootp, fragment)


class NetworkEvidenceTests(unittest.TestCase):
    def test_fragmented_ack(self):
        report = analyze(session(fragment=True))
        self.assertTrue(report['guest_pan_ip_configuration_observed'])
        self.assertEqual(report['dhcp'][0]['assigned_ip'], '10.19.241.96')
        self.assertFalse(report['external_internet_reachability_verified'])

    def test_offer_does_not_prove_lease(self):
        self.assertFalse(analyze(session(ack=2))['guest_pan_ip_configuration_observed'])

    def test_incomplete_fragment_does_not_prove_lease(self):
        self.assertFalse(analyze(session(fragment=True)[:-1])['guest_pan_ip_configuration_observed'])


if __name__ == '__main__':
    unittest.main()
