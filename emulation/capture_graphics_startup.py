#!/usr/bin/env python3
"""Capture original native EGL/PowerVR startup through QEMU's local GDB socket.
Use a private COPY of nand-complete.raw. Start QEMU with -S -gdb unix:PATH,
server=on,wait=off, then run this script. Breakpoints and physical-memory reads
are debugger operations; no guest firmware bytes or return values are patched.
The script detaches/resumes after the Qt capability query or max-events limit.
"""
import argparse
import hashlib
import json
import socket
import struct
from pathlib import Path

POINTS = {
    0x02018ec4: 'PVRSRVConnect return',
    0x02018f08: 'PVRSRVEnumerateDevices return',
    0x02018f60: 'PVRSRVAcquireDeviceData return',
    0x02018f84: 'PVRSRVGetMBXInfo return',
    0x02018fc8: 'PVRSRVGetMiscInfo return',
    0x020144a0: 'SRV_ServicesInit return',
    0x020144d4: 'WS initialize return',
    0x01fc8650: 'eglInitialize return',
    0x01fc8d64: 'eglCreateContext return',
    0x01fc85e8: 'eglMakeCurrent return',
    0x01df6e00: 'Qt maxTextureSize query return',
}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--application', type=Path,
                        default=Path('artifacts/phase2/applications/NAV/app.bin'))
    parser.add_argument('--timeout', type=float, default=120)
    parser.add_argument('--max-events', type=int, default=64)
    args = parser.parse_args()
    app = args.application.read_bytes()
    report = {'application': str(args.application),
              'application_sha256': hashlib.sha256(app).hexdigest(),
              'firmware_modified': False, 'events': []}
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(args.timeout)
    sock.connect(args.socket)

    def receive():
        while True:
            char = sock.recv(1)
            if not char:
                raise RuntimeError('GDB socket closed')
            if char == b'$':
                break
        body = bytearray()
        while True:
            char = sock.recv(1)
            if char == b'#':
                break
            if not char:
                raise RuntimeError('GDB packet truncated')
            body.extend(char)
        checksum = sock.recv(2)
        if int(checksum, 16) != sum(body) % 256:
            raise RuntimeError('GDB packet checksum mismatch')
        sock.sendall(b'+')
        return body.decode()

    def request(command):
        raw = command.encode()
        sock.sendall(b'$' + raw + b'#' + f'{sum(raw) % 256:02x}'.encode())
        return receive()

    def register(number):
        return int(request(f'p{number:x}'), 16)

    def memory(address, length):
        value = request(f'm{address:x},{length:x}')
        if value.startswith('E'):
            raise RuntimeError(f'GDB memory read failed: {address:x}: {value}')
        return bytes.fromhex(value)

    def word(address):
        return struct.unpack('>I', memory(address, 4))[0]

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')

    print(request('qSupported'), request('?'), flush=True)
    if request('Qqemu.PhyMemMode:1') != 'OK':
        raise RuntimeError('Physical-memory debugger mode unavailable')
    for pc in POINTS:
        if request(f'Z0,{pc:x},4') != 'OK':
            raise RuntimeError(f'Breakpoint unavailable: {pc:x}')
    can_cleanup = True
    try:
        for _ in range(args.max_events):
            stop = request('c')
            pc = register(64)
            regs = {str(i): hex(register(i)) for i in range(32)}
            regs.update({str(i): hex(register(i)) for i in [64, 65, 66, 67]})
            expected = app[pc - 0x01000000:pc - 0x01000000 + 4]
            actual = memory(pc, 4)
            event = {'stop': stop, 'pc': hex(pc), 'name': POINTS.get(pc),
                     'result_r3': regs['3'], 'registers': regs,
                     'original_instruction_hex': expected.hex(),
                     'runtime_instruction_hex': actual.hex(),
                     'instruction_matches_original': actual == expected,
                     'OGL_TLS_mode': hex(word(0x036d2a24)),
                     'OGL_singleton_context': hex(word(0x036d29b0))}
            if pc == 0x01df6e00:
                context = int(regs['31'], 16)
                event['Qt_context'] = hex(context)
                event['Qt_max_texture_size'] = hex(word(context + 0xf8))
            report['events'].append(event)
            save()
            print(json.dumps({key: value for key, value in event.items()
                              if key != 'registers'}), flush=True)
            if pc == 0x01df6e00 or pc not in POINTS:
                break
            request(f'z0,{pc:x},4')
            request('s')
            request(f'Z0,{pc:x},4')
    except Exception as error:
        report['capture_error'] = str(error)
        save()
        # A timeout during 'c' leaves the CPU running. Attempt a bounded interrupt
        # before issuing further requests; never queue dozens of blocked packets.
        sock.settimeout(5)
        try:
            sock.sendall(b'\x03')
            report['interrupt_after_error'] = receive()
        except Exception:
            can_cleanup = False
        save()
        raise
    finally:
        if can_cleanup:
            for pc in POINTS:
                request(f'z0,{pc:x},4')
            request('D')
        sock.close()

if __name__ == '__main__':
    main()
