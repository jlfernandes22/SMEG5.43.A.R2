"""Guarded legacy global-encryption workaround for public name lookup only.

The measured MediaTek controller rejects Remote Name Request after the SMEG
sets Encryption_Mode=1. Temporarily suspend that legacy setting only while
scan is disabled, before any connection attempt. Restore it before releasing
name completion or any queued guest traffic. Never synthesize RF success.
"""
from collections import deque
import time

ENCRYPT_OFF = bytes.fromhex('01220c0100')
ENCRYPT_ON = bytes.fromhex('01220c0101')
AUTH_ON = bytes.fromhex('01200c0101')

class LegacyNameRequest:
    def __init__(self, record=lambda *args, **kwargs: None):
        self.record = record
        self.encryption_mode = 0
        self.scan_enable = 0
        self.authentication_enabled = 0
        self.connection_seen = False
        self.pending = {}
        self.state = 'idle'
        self.deferred = deque()
        self.request = None
        self.held = None
        self.deadline = None

    def guest(self, packet):
        if self.state != 'idle':
            if len(self.deferred) >= 256:
                raise BufferError('Name-lookup deferred queue exceeded256 packets')
            self.deferred.append(packet)
            return []
        if packet[0] in (2, 3, 5):
            self.connection_seen = True
        if packet[0] != 1:
            return [packet]
        opcode = int.from_bytes(packet[1:3], 'little')
        if opcode in (0x0405, 0x0407, 0x0409, 0x0428, 0x0429, 0x043d, 0x043e):
            self.connection_seen = True
        if opcode in (0x0c22, 0x0c1a, 0x0c20) and len(packet) == 5:
            self.pending[opcode] = packet[4]
        if (opcode in (0x0405, 0x0409) and self.encryption_mode == 1 and
                not self.authentication_enabled):
            # Authentication-first compatibility experiment. Global
            # encryption stays enabled; no fake link or security success.
            self.state = 'authentication'
            self.request = packet
            self.deadline = time.monotonic() + 15
            self.record('legacy_connection_authentication_begin')
            return [AUTH_ON]
        if (opcode == 0x0419 and len(packet) == 14 and
                self.encryption_mode == 1 and self.scan_enable == 0 and
                not self.connection_seen):
            self.state = 'disable'
            self.request = packet
            self.deadline = time.monotonic() + 15
            self.record('legacy_name_begin', scan_enable=0, prior_encryption_mode=1)
            return [ENCRYPT_OFF]
        return [packet]

    def _drain(self):
        output = []
        while self.deferred and self.state == 'idle':
            output.extend(self.guest(self.deferred.popleft()))
        return output

    def radio(self, packet):
        """Return (unchanged guest events, real-controller commands)."""
        event = packet[1] if len(packet) >= 2 and packet[0] == 4 else None
        if packet[0] in (2, 3, 5) or event in (3, 4):
            self.connection_seen = True
            if self.state in ('disable', 'name', 'restore'):
                raise RuntimeError('Unexpected connection during isolated name lookup; closing radio lease')
        opcode = int.from_bytes(packet[4:6], 'little') if event == 0x0e and len(packet) >= 7 else None
        status = packet[6] if opcode is not None else None
        if self.state == 'authentication' and opcode == 0x0c20:
            self.record('legacy_connection_authentication_complete', status=status)
            if status == 0:
                self.authentication_enabled = 1
            request = self.request
            self.state = 'idle'
            self.deadline = None
            return [], [request] + self._drain()
        if self.state == 'disable' and opcode == 0x0c22:
            self.record('legacy_name_disable_complete', status=status)
            if status:
                request = self.request
                self.state = 'idle'
                # Try the unmodified request under the original policy; do
                # not fabricate its command status if the workaround failed.
                return [], [request] + self._drain()
            self.state = 'name'
            return [], [self.request]
        if self.state == 'restore' and opcode == 0x0c22:
            self.record('legacy_name_restore_complete', status=status)
            if status:
                raise RuntimeError('Could not restore global encryption mode; closing radio lease')
            held = self.held
            self.held = None
            self.state = 'idle'
            self.deadline = None
            return [held], self._drain()
        if self.state == 'name':
            failed = (event == 0x0f and len(packet) >= 7 and
                      packet[5:7] == bytes.fromhex('1904') and packet[3] != 0)
            finished = (event == 7 and len(packet) >= 10 and
                        packet[4:10] == self.request[4:10])
            if failed or finished:
                self.held = packet
                self.state = 'restore'
                return [], [ENCRYPT_ON]
        if opcode == 0x0c03 and status == 0:
            self.encryption_mode = self.scan_enable = 0
            self.authentication_enabled = 0
            self.connection_seen = False
            self.pending.clear()
        if opcode in self.pending:
            value = self.pending.pop(opcode)
            if status == 0:
                if opcode == 0x0c22:
                    self.encryption_mode = value
                elif opcode == 0x0c20:
                    self.authentication_enabled = value
                else:
                    self.scan_enable = value
        return [packet], []

    def tick(self):
        if self.state != 'idle' and self.deadline is not None and time.monotonic() > self.deadline:
            raise TimeoutError('Isolated name lookup timed out; closing radio lease to restore host state')
