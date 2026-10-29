"""Offline socket tests. The live forwarding path uses a socketpair, never a radio."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
BRIDGE=Path(__file__).with_name('hci_bridge.py')
class SocketTests(unittest.TestCase):
    def start(self,directory,mode,radio_fd=None,bond_fd=None):
        endpoint=Path(directory)/'hci.sock';log=Path(directory)/'hci.jsonl'
        cmd=[sys.executable,str(BRIDGE),'--mode',mode,'--socket',str(endpoint),'--log',str(log)]
        fds=()
        if radio_fd is not None:cmd+=['--radio-fd',str(radio_fd)];fds=(radio_fd,)
        if bond_fd is not None:
            cmd+=['--bond-fd',str(bond_fd),'--bond-peer','22:22:4D:F1:4E:5E'];fds+=(bond_fd,)
        process=subprocess.Popen(cmd,pass_fds=fds,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        deadline=time.monotonic()+3
        while not endpoint.exists() and process.poll() is None and time.monotonic()<deadline:time.sleep(.01)
        self.assertTrue(endpoint.exists(),process.stderr.read().decode() if process.poll() is not None else 'not ready')
        peer=socket.socket(socket.AF_UNIX);peer.settimeout(2);peer.connect(str(endpoint))
        self.addCleanup(peer.close)
        def cleanup():
            if process.poll() is None:process.terminate()
            process.wait(timeout=3);process.stderr.close()
        self.addCleanup(cleanup)
        return process,peer,endpoint,log
    def receive(self,s,n):
        data=bytearray()
        while len(data)<n:data+=s.recv(n-len(data))
        return bytes(data)
    def test_fragmented_reset_and_explicit_unsupported(self):
        with tempfile.TemporaryDirectory() as d:
            process,peer,endpoint,log=self.start(d,'probe')
            for byte in bytes.fromhex('01030c00'):peer.sendall(bytes([byte]))
            self.assertEqual(self.receive(peer,7),bytes.fromhex('040e0401030c00'))
            peer.sendall(bytes.fromhex('0105fc00'))
            self.assertEqual(self.receive(peer,7),bytes.fromhex('040e040105fc01'))
            peer.close();self.assertEqual(process.wait(timeout=3),0)
            self.assertFalse(endpoint.exists())
            events=[json.loads(l)for l in log.read_text().splitlines()]
            self.assertFalse(events[0]['radio_enabled'])
    def test_infineon_overlay_keeps_real_core_responses(self):
        with tempfile.TemporaryDirectory() as d:
            controller,bridge=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
            self.addCleanup(controller.close);self.addCleanup(bridge.close);controller.settimeout(.15)
            process,peer,_,_=self.start(d,'infineon-live',bridge.fileno())
            reset=bytes.fromhex('01030c00');peer.sendall(reset)
            self.assertEqual(controller.recv(65540),reset)
            actual=bytes.fromhex('040e0401030c00');controller.send(actual)
            self.assertEqual(self.receive(peer,11),actual+bytes.fromhex('04ff0100'))
            peer.sendall(bytes.fromhex('0105fc00'))
            self.assertEqual(self.receive(peer,10),bytes.fromhex('040e070105fc00000023'))
            with self.assertRaises(socket.timeout):controller.recv(65540)
            # Standard core opcodes keep the real controller's identity/caps.
            request=bytes.fromhex('01011000');peer.sendall(request)
            self.assertEqual(controller.recv(65540),request)
            response=bytes.fromhex('040e0c010110000c00000c46000000');controller.send(response)
            self.assertEqual(self.receive(peer,len(response)),response)
            peer.close();self.assertEqual(process.wait(timeout=3),0)
    def test_baud_event_arrives_after_command_completion(self):
        with tempfile.TemporaryDirectory() as d:
            process,peer,_,_=self.start(d,'infineon-probe')
            peer.sendall(bytes.fromhex('0106fc010b'))
            self.assertEqual(self.receive(peer,7),bytes.fromhex('040e040106fc00'))
            peer.settimeout(.05)
            with self.assertRaises(socket.timeout):peer.recv(4)
            peer.settimeout(2)
            self.assertEqual(self.receive(peer,4),bytes.fromhex('04ff0112'))
            peer.close();self.assertEqual(process.wait(timeout=3),0)
    def test_real_name_is_held_until_real_encryption_restore(self):
        with tempfile.TemporaryDirectory() as d:
            controller,bridge=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
            self.addCleanup(controller.close);self.addCleanup(bridge.close);controller.settimeout(2)
            process,peer,_,_=self.start(d,'infineon-live',bridge.fileno())
            encryption=bytes.fromhex('01220c0101');completion=bytes.fromhex('040e0401220c00')
            peer.sendall(encryption);self.assertEqual(controller.recv(65540),encryption)
            controller.send(completion);self.assertEqual(self.receive(peer,7),completion)
            request=bytes.fromhex('0119040a5e4ef14d222201000000');peer.sendall(request)
            self.assertEqual(controller.recv(65540),bytes.fromhex('01220c0100'))
            controller.send(completion);self.assertEqual(controller.recv(65540),request)
            status=bytes.fromhex('040f0400011904');controller.send(status)
            self.assertEqual(self.receive(peer,7),status)
            payload=bytes.fromhex('005e4ef14d2222')+b'OnePlus 12'.ljust(248,b'\0')
            name=b'\x04\x07\xff'+payload;controller.send(name)
            self.assertEqual(controller.recv(65540),encryption)
            peer.settimeout(.05)
            with self.assertRaises(socket.timeout):peer.recv(65540)
            peer.settimeout(2);controller.send(completion)
            self.assertEqual(self.receive(peer,len(name)),name)
            peer.close();self.assertEqual(process.wait(timeout=3),0)
    def test_existing_bond_answers_actual_challenge_without_logging_key(self):
        with tempfile.TemporaryDirectory() as d:
            controller,bridge=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
            self.addCleanup(controller.close);self.addCleanup(bridge.close);controller.settimeout(2)
            fd=os.memfd_create('test-only-synthetic-bond');self.addCleanup(os.close,fd)
            key=bytes(range(16));os.write(fd,key);os.lseek(fd,0,os.SEEK_SET)
            process,peer,_,log=self.start(d,'infineon-live',bridge.fileno(),fd)
            address=bytes.fromhex('5e4ef14d2222')
            controller.send(b'\x04\x17\x06'+address)
            self.assertEqual(controller.recv(65540),b'\x01\x0b\x04\x16'+address+key)
            controller.send(bytes.fromhex('040e0a010b0400')+address)
            peer.settimeout(.05)
            with self.assertRaises(socket.timeout):peer.recv(65540)
            peer.settimeout(2)
            actual=bytes.fromhex('04030b0001005e4ef14d22220101');controller.send(actual)
            self.assertEqual(self.receive(peer,len(actual)),actual)
            peer.close();self.assertEqual(process.wait(timeout=3),0)
            self.assertNotIn(key.hex(),log.read_text())
            self.assertIn('existing_host_bond_reused',log.read_text())
    def test_opaque_forwarding_without_physical_radio(self):
        with tempfile.TemporaryDirectory() as d:
            controller,bridge=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
            self.addCleanup(controller.close);self.addCleanup(bridge.close);controller.settimeout(2)
            process,peer,_,_=self.start(d,'live',bridge.fileno())
            for raw in ['0105fc02abcd','0201000300010203','030100020102','05010002000102']:
                packet=bytes.fromhex(raw);peer.sendall(packet)
                self.assertEqual(controller.recv(65540),packet)
            event=bytes.fromhex('040e040105fc01');controller.send(event)
            self.assertEqual(self.receive(peer,len(event)),event)
            peer.close();self.assertEqual(process.wait(timeout=3),0)
if __name__=='__main__':unittest.main()
