#!/usr/bin/env python3
"""PSC1 H4 bridge with optional native-derived Infineon compatibility.

Probe has no radio and never invents scan results, links, pairing or IP access.
Plain live forwards packets unchanged. Infineon-live models vendor startup and
guards the measured legacy-encryption/public-name compatibility sequence.
Stop BlueZ ownership/power before HCI_CHANNEL_USER and restore it on exit.
"""
import argparse
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import struct
import time
from hci_legacy_name import LegacyNameRequest

MAX_H4 = 65540
class H4Parser:
    def __init__(self): self.buffer = bytearray()
    def feed(self, data):
        self.buffer.extend(data)
        packets = []
        while self.buffer:
            kind = self.buffer[0]
            header = {1:4,2:5,3:4,4:3,5:5}.get(kind)
            if header is None: raise ValueError(f'Invalid H4 type0x{kind:02x}')
            if len(self.buffer) < header: break
            if kind in (1,3): size = self.buffer[3]
            elif kind == 4: size = self.buffer[2]
            else:
                size = int.from_bytes(self.buffer[3:5], 'little')
                if kind == 5: size &= 0x3fff
            length = header + size
            if length > MAX_H4: raise ValueError('H4 packet exceeds bound')
            if len(self.buffer) < length: break
            packets.append(bytes(self.buffer[:length]));del self.buffer[:length]
        if len(self.buffer) > MAX_H4: raise ValueError('H4 buffer exceeds bound')
        return packets

def complete(opcode, result=b'\0'):
    payload = b'\x01' + struct.pack('<H', opcode) + result
    return b'\x04\x0e' + bytes([len(payload)]) + payload

class ProbeController:
    """Limited HCI initialization fixture, deliberately not a virtual phone."""
    def __init__(self, infineon=False):
        self.infineon = infineon
        self.manufacturer_mode = False
        self.memory = {}
        self.board_data = bytearray(60)
        self.baud_code = None
        self.delayed_events = []
    def ready_events(self, now=None):
        now = time.monotonic() if now is None else now
        ready = [packet for due, packet in self.delayed_events if due <= now]
        self.delayed_events = [(due, packet) for due, packet in self.delayed_events if due > now]
        return ready
    def command(self, packet):
        if packet[0] != 1: return []
        opcode = int.from_bytes(packet[1:3], 'little')
        params = packet[4:]
        if opcode == 0x0c03:
            if params:return [complete(opcode,b'\x12')]
            self.manufacturer_mode = False
            self.delayed_events.clear()
            result=[complete(opcode)]
            if self.infineon:result.append(bytes.fromhex('04ff0100'))
            return result  # Reset
        if self.infineon and opcode == 0xfc05:
            if params:return [complete(opcode,b'\x12')]
            # Minimal virtual revision2.3 register profile. Native1776ce0
            # reads response-data[2], accepting23/24. Not measured car data.
            return [complete(opcode,bytes.fromhex('00000023'))]
        if self.infineon and opcode == 0xfc11:
            if len(params)!=2 or params[0] not in (0,1) or params[1] not in (0,1,2):
                return [complete(opcode,b'\x12')]
            self.manufacturer_mode = bool(params[0])
            return [complete(opcode)]
        if self.infineon and opcode == 0xfc8e:
            # Native BTALInfineonMemoryWrite17772a0: LE32 address,
            # observed mode0/2, byte count, then exactly that many bytes. Writes affect
            # virtual memory only; there is no host/radio vendor passthrough.
            if len(params)<6 or params[4] not in (0,2) or len(params)!=6+params[5]:
                return [complete(opcode,b'\x12')]
            if not self.manufacturer_mode:return [complete(opcode,b'\x0c')]
            address=int.from_bytes(params[:4],'little');data=params[6:]
            if address+len(data)>0x100000000 or len(self.memory)+len(data)>1024*1024:
                return [complete(opcode,b'\x07')]
            self.memory.update((address+i,byte)for i,byte in enumerate(data))
            return [complete(opcode)]
        if self.infineon and opcode == 0xfc30:
            if params:return [complete(opcode,b'\x12')]
            # Explicit virtual blank board-data storage. The native caller
            # requests60 bytes, writes58, and configures it through fc2f.
            return [complete(opcode,b'\0'+self.board_data)]
        if self.infineon and opcode == 0xfc2f:
            if len(params)!=58:return [complete(opcode,b'\x12')]
            if not self.manufacturer_mode:return [complete(opcode,b'\x0c')]
            self.board_data[:58]=params
            return [complete(opcode),bytes.fromhex('04ff0100')]
        if self.infineon and opcode == 0xfc06:
            # Captured native baud-change request: code0b. The actual host
            # controller is USB, so this changes only the virtual UART side.
            if params!=b'\x0b':return [complete(opcode,b'\x12')]
            self.baud_code=params[0]
            # Native1776f88 flushes its event queue before closing/reopening
            # UART, then1777130 requires vendor payload12 (baud changed).
            # Delay models the wire-rate transition; not a measured timing.
            self.delayed_events.append((time.monotonic()+.2,bytes.fromhex('04ff0112')))
            return [complete(opcode)]
        # Unknown controller/vendor operations fail explicitly, never success.
        return [complete(opcode, b'\x01')]

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode',choices=['probe','infineon-probe','live','infineon-live'],required=True)
    p.add_argument('--socket',type=Path,required=True)
    p.add_argument('--log',type=Path,required=True)
    p.add_argument('--controller',type=int,default=0)
    p.add_argument('--radio-fd',type=int,help=argparse.SUPPRESS)
    p.add_argument('--bond-fd',type=int,help=argparse.SUPPRESS)
    p.add_argument('--bond-peer',help=argparse.SUPPRESS)
    a=p.parse_args()
    bond=None;bond_reply_pending=False
    if a.bond_fd is not None:
        if a.mode!='infineon-live' or not a.bond_peer:p.error('Existing bond requires Infineon live mode and peer')
        peer_address=bytes.fromhex(a.bond_peer.replace(':',''))[::-1]
        key=os.read(a.bond_fd,17);os.close(a.bond_fd)
        if len(peer_address)!=6 or len(key)!=16:p.error('Invalid inherited bond')
        bond=(peer_address,key)
    def stop(signum, frame): raise SystemExit(0)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    if a.controller < 0: p.error('controller index must be nonnegative')
    a.socket.parent.mkdir(parents=True,exist_ok=True);a.log.parent.mkdir(parents=True,exist_ok=True)
    # Never unlink an existing endpoint, which might belong to another VM.
    server=socket.socket(socket.AF_UNIX);server.bind(str(a.socket));os.chmod(a.socket,0o600);server.listen(1)
    radio=None;peer=None;sel=selectors.DefaultSelector();probe=ProbeController(infineon=a.mode.startswith('infineon-'))
    with a.log.open('a',buffering=1) as log:
        # HCI pairing traffic can contain link keys. Keep raw captures private.
        os.chmod(a.log,0o600)
        def record(event,**kw):
            log.write(json.dumps({'monotonic':time.monotonic(),'mode':a.mode,'event':event,**kw})+'\n')
        def record_packet(event,packet,**kw):
            command=int.from_bytes(packet[1:3],'little') if packet[0]==1 else None
            code=packet[1] if packet[0]==4 else None
            if command in (0x040b,0x040d,0x0c11) or code in (0x15,0x18):
                record(event,h4_type=packet[0],event_code=code,key_material='redacted',**kw)
            else:record(event,hex=packet.hex(),**kw)
        try:
            if a.mode.endswith('live'):
                radio=(socket.socket(fileno=a.radio_fd) if a.radio_fd is not None else
                       socket.socket(socket.AF_BLUETOOTH,socket.SOCK_RAW,socket.BTPROTO_HCI))
                if a.radio_fd is None:radio.bind((a.controller,1))  # Linux HCI_CHANNEL_USER, exclusive
                radio.setblocking(False);sel.register(radio,selectors.EVENT_READ,'radio')
            record('listening',controller=a.controller if radio else None,radio_enabled=bool(radio and radio.family==socket.AF_BLUETOOTH),
                   transport_fd_provided=a.radio_fd is not None)
            print(json.dumps({'listening':str(a.socket),'mode':a.mode}),flush=True)
            # If QEMU fails before connecting, release an exclusive radio
            # promptly rather than spending the entire lease in accept().
            server.settimeout(20)
            peer,_=server.accept();peer.setblocking(False);sel.register(peer,selectors.EVENT_READ,'guest')
            parsers={'guest':H4Parser(),'radio':H4Parser()};queues={'guest':bytearray(),'radio':[]}
            def queue_guest(packet):
                if len(queues['guest'])+len(packet)>1024*1024:raise BufferError('guest output backlog exceeded1MiB')
                queues['guest'].extend(packet)
            legacy_name=LegacyNameRequest(record) if a.mode=='infineon-live' else None
            def queue_radio(packet, internal=False, private=False):
                if len(queues['radio'])>=256:raise BufferError('radio backlog exceeded256packets')
                if private:record('existing_bond_radio_reply',opcode='0x040b',key_material='redacted')
                elif internal:record_packet('compatibility_radio_command',packet,simulated=False)
                queues['radio'].append(packet)
            while True:
                if legacy_name:legacy_name.tick()
                for response in probe.ready_events():
                    record('virtual_controller_event',hex=response.hex(),simulated=True)
                    queue_guest(response)
                for key,_ in sel.select(.01):
                    kind=key.data
                    try:data=key.fileobj.recv(MAX_H4)
                    except BlockingIOError:continue
                    if not data:record('disconnected',endpoint=kind);return
                    for packet in parsers[kind].feed(data):
                        opcode=f'0x{int.from_bytes(packet[1:3],"little"):04x}' if packet[0]==1 else None
                        record_packet('packet',packet,direction=kind,opcode=opcode)
                        if kind=='radio':
                            if bond and packet==b'\x04\x17\x06'+bond[0]:
                                # Virtual controller's existing-key store answers
                                # a real RF challenge. No new pair/key is invented.
                                queue_radio(b'\x01\x0b\x04\x16'+bond[0]+bond[1],private=True)
                                bond_reply_pending=True
                                record('existing_host_bond_reused',peer=a.bond_peer,simulated=False)
                                continue
                            if (bond_reply_pending and len(packet)>=7 and packet[:2]==b'\x04\x0e'and
                                    packet[4:6]==b'\x0b\x04'):
                                bond_reply_pending=False
                                record('existing_bond_reply_complete',status=packet[6],simulated=False)
                                continue
                            if a.mode=='infineon-live' and packet[:2]==bytes.fromhex('04ff'):
                                record('foreign_vendor_event_filtered',hex=packet.hex())
                                continue
                            if legacy_name:
                                guest_packets,commands=legacy_name.radio(packet)
                                for response in guest_packets:queue_guest(response)
                                for command in commands:queue_radio(command,internal=True)
                            else:queue_guest(packet)
                            # Native17775ec..17777ac waits for an Infineon boot
                            # event in addition to an actual successful Reset.
                            # This is explicit virtual-controller behavior;
                            # physical command completion is never fabricated.
                            if (a.mode=='infineon-live' and len(packet)>=7 and
                                packet[:2]==bytes.fromhex('040e') and
                                packet[4:7]==bytes.fromhex('030c00')):
                                boot=bytes.fromhex('04ff0100')
                                record('virtual_controller_event',hex=boot.hex(),simulated=True)
                                queue_guest(boot)
                        elif radio:
                            opcode=int.from_bytes(packet[1:3],'little') if packet[0]==1 else None
                            if a.mode=='infineon-live' and opcode is not None:
                                if opcode==0x0c03:probe.command(packet)
                                if opcode>>10==0x3f:
                                    for response in probe.command(packet):
                                        record('virtual_controller_response',hex=response.hex(),simulated=True)
                                        queue_guest(response)
                                    continue
                            if legacy_name:
                                commands=legacy_name.guest(packet)
                                for command in commands:queue_radio(command,internal=command!=packet)
                            else:queue_radio(packet)
                        else:
                            for response in probe.command(packet):
                                record('probe_response',hex=response.hex(),simulated=True);queue_guest(response)
                if queues['guest']:
                    try:
                        n=peer.send(queues['guest']);del queues['guest'][:n]
                    except BlockingIOError:pass
                if radio and queues['radio']:
                    try:
                        packet=queues['radio'][0];n=radio.send(packet)
                        if n!=len(packet):raise RuntimeError('Partial HCI datagram')
                        del queues['radio'][0]
                    except BlockingIOError:pass
        except Exception as exc:
            record('error',type=type(exc).__name__,message=str(exc));raise
        finally:
            sel.close()
            if peer:peer.close()
            if radio:radio.close()
            server.close();a.socket.unlink(missing_ok=True)

if __name__=='__main__': main()
