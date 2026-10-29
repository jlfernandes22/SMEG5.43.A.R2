#!/usr/bin/env python3
"""Run genuine firmware for a bounded time; preserve serial, monitor and TCG logs."""
import argparse
import json
import os
import subprocess
import time
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--seconds', type=float, default=10)
p.add_argument('--tag', default='boot')
p.add_argument('--monitor-command', action='append', default=[])
p.add_argument('--debug', default='cpu_reset,unimp,guest_errors')
p.add_argument('--trace-range', action='append', default=[],
               help='QEMU -dfilter range; can repeat to trace native app entries')
p.add_argument('--capture-at', action='append', default=[], metavar='SECONDS:FILE',
               help='Capture the actual QEMU display surface at elapsed time')
p.add_argument('--stop-on-serial',
               help='Stop after this literal string appears in original UART output')
p.add_argument('--until-shell', action='store_true')
a = p.parse_args()
captures=[]
for value in a.capture_at:
    when, separator, filename=value.partition(':')
    if not separator or not filename:
        p.error('--capture-at requires SECONDS:FILE')
    captures.append((float(when), str(Path(filename).resolve())))
captures.sort()
out = Path('artifacts/phase3')
out.mkdir(parents=True, exist_ok=True)
trace = out / (a.tag + '.qemu.log')
serial = out / (a.tag + '.serial.log')
cmd = ['bash', 'emulation/launch.sh', '-d', a.debug,
       '-D', str(trace.resolve()), '-monitor', 'stdio']
if a.trace_range:
    cmd += ['-dfilter', ','.join(a.trace_range)]
env = dict(os.environ, SMEG_SERIAL='file:' + str(serial.resolve()))
monitor = out / (a.tag + '.monitor.log')
monitor_stream = monitor.open('wb')
proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=monitor_stream,
                        stderr=subprocess.STDOUT, env=env)
try:
    started=time.monotonic()
    deadline = started + a.seconds
    while proc.poll() is None:
        while captures and time.monotonic()-started >= captures[0][0]:
            _, filename=captures.pop(0)
            proc.stdin.write(('screendump '+json.dumps(filename)+'\n').encode())
            proc.stdin.flush()
        if a.stop_on_serial and serial.exists() and a.stop_on_serial.encode() in serial.read_bytes():
            raise subprocess.TimeoutExpired(cmd, a.seconds)
        if a.until_shell and serial.exists() and b'\n-> ' in serial.read_bytes():
            raise subprocess.TimeoutExpired(cmd, a.seconds)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(cmd, a.seconds)
        try:
            proc.wait(timeout=min(1, remaining))
        except subprocess.TimeoutExpired:
            pass
    output, _ = proc.communicate()
    status = 'exited'
except subprocess.TimeoutExpired:
    try:
        commands = ['info registers', *a.monitor_command, 'quit']
        output, _ = proc.communicate(input=('\n'.join(commands)+'\n').encode(), timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        output, _ = proc.communicate()
    status = 'timeout'
monitor_stream.close()
output = monitor.read_bytes()
print(json.dumps({'command': cmd, 'status': status, 'returncode': proc.returncode,
                  'serial': str(serial), 'trace': str(trace)}))
if serial.exists():
    print(serial.read_text(errors='replace')[-6000:])
print(output.decode(errors='replace')[-5000:])
