#!/usr/bin/env python3
"""Execute native VxWorks shell inspection through the emulated UART RX path."""
import argparse
import os
from pathlib import Path
import subprocess
import time

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--seconds', type=float, default=120)
p.add_argument('--tag', default='mount-check')
a = p.parse_args()
out = Path('artifacts/phase3')
serial = out / (a.tag + '.serial.log')
env = dict(os.environ, SMEG_SERIAL='stdio')
commands = b'\rdevs\rdosFsShow "/SYSTEM_DATA", 2\rls "/SYSTEM_DATA"\r'
with serial.open('wb') as stream, (out / (a.tag + '.host.log')).open('wb') as errors:
    proc = subprocess.Popen(['bash', 'emulation/launch.sh', '-monitor', 'none',
        '-d', 'cpu_reset,unimp,guest_errors', '-D', str((out / (a.tag + '.qemu.log')).resolve())],
        stdin=subprocess.PIPE, stdout=stream, stderr=errors, env=env)
    deadline = time.monotonic() + a.seconds
    sent = None
    try:
        while proc.poll() is None and time.monotonic() < deadline:
            content = serial.read_bytes()
            if sent is None and b'\n-> ' in content:
                proc.stdin.write(commands)
                proc.stdin.flush()
                sent = time.monotonic()
            if sent and time.monotonic() - sent > 12:
                break
            try:
                proc.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                pass
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
print(serial.read_text(errors='replace')[-16000:])
if sent is None:
    raise SystemExit('No guest shell prompt; no shell commands were injected')
