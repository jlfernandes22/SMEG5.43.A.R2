import unittest
from hci_bridge import H4Parser,ProbeController,complete
class ProtocolTests(unittest.TestCase):
    def test_fragmentation_and_coalescing(self):
        packets=[bytes.fromhex(s)for s in ['01030c00','040e0401030c00','0201000300010203','030100020102','05010002000102']]
        raw=b''.join(packets)
        for n in range(1,len(raw)+1):
            p=H4Parser();out=[]
            for off in range(0,len(raw),n):out+=p.feed(raw[off:off+n])
            self.assertEqual(out,packets);self.assertFalse(p.buffer)
    def test_invalid_type(self):
        with self.assertRaises(ValueError):H4Parser().feed(b'\xff')
    def test_probe_fails_unknown_commands(self):
        c=ProbeController()
        self.assertEqual(c.command(bytes.fromhex('01030c00')),[bytes.fromhex('040e0401030c00')])
        self.assertEqual(c.command(bytes.fromhex('0105fc00')),[complete(0xfc05,b'\x01')])
        self.assertEqual(c.command(bytes.fromhex('0201000000')),[])
    def test_infineon_reset_boot_contract(self):
        c=ProbeController(infineon=True)
        self.assertEqual(c.command(bytes.fromhex('01030c00')),
                         [bytes.fromhex('040e0401030c00'),bytes.fromhex('04ff0100')])
        self.assertEqual(c.command(bytes.fromhex('01030c0100')),[complete(0x0c03,b'\x12')])
    def test_infineon_register_state(self):
        c=ProbeController(infineon=True)
        self.assertEqual(c.command(bytes.fromhex('0105fc00')),[complete(0xfc05,bytes.fromhex('00000023'))])
        write=bytes.fromhex('018efc0a00000040020401236200')
        self.assertEqual(c.command(write),[complete(0xfc8e,b'\x0c')])
        self.assertEqual(c.command(bytes.fromhex('0111fc020100')),[complete(0xfc11)])
        self.assertEqual(c.command(write),[complete(0xfc8e)])
        self.assertEqual(bytes(c.memory[0x40000000+i]for i in range(4)),bytes.fromhex('01236200'))
        self.assertEqual(c.command(bytes.fromhex('018efc06000000400204')),[complete(0xfc8e,b'\x12')])
    def test_board_data_readback(self):
        c=ProbeController(infineon=True)
        c.command(bytes.fromhex('0111fc020100'))
        data=bytes(range(58));result=c.command(bytes.fromhex('012ffc3a')+data)
        self.assertEqual(result,[complete(0xfc2f),bytes.fromhex('04ff0100')])
        self.assertEqual(c.command(bytes.fromhex('0130fc00')),[complete(0xfc30,b'\0'+data+b'\0\0')])
    def test_observed_baud_code(self):
        c=ProbeController(infineon=True)
        self.assertEqual(c.command(bytes.fromhex('0106fc010b')),
                         [complete(0xfc06)])
        self.assertEqual(c.baud_code,11)
        self.assertEqual(c.ready_events(now=0),[])
        self.assertEqual(c.ready_events(now=float('inf')),[bytes.fromhex('04ff0112')])
        self.assertEqual(c.ready_events(now=float('inf')),[])
        self.assertEqual(c.command(bytes.fromhex('0106fc010a')),[complete(0xfc06,b'\x12')])
        c.command(bytes.fromhex('0106fc010b'))
        c.command(bytes.fromhex('01030c00'))
        self.assertEqual(c.ready_events(now=float('inf')),[])
    def test_max_acl(self):
        raw=b'\x02\x01\x00\xff\xff'+bytes(65535)
        p=H4Parser();self.assertEqual(p.feed(raw[:5]),[]);self.assertEqual(p.feed(raw[5:]),[raw])
if __name__=='__main__':unittest.main()
