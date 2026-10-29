#!/usr/bin/env python3
"""Compile the actual board UART functions with a deterministic clock and sink."""
from pathlib import Path
import subprocess,tempfile
root=Path(__file__).resolve().parent
s=(root/'mpc5121e_smeg.c').read_text()
a=s.index('#define SMEG_UART_BYTE_NS');b=s.index('static uint32_t smeg_fifo_pending(',a)
c=s.index('static void smeg_uart_tx_drain(');d=s.index('static int smeg_serial_can_receive(',c)
with tempfile.TemporaryDirectory(prefix='smeg-uart-deadline-') as name:
 p=Path(name);(p/'uart_production.inc').write_text(s[a:b]+s[c:d])
 subprocess.run(['cc','-std=c11','-O2','-Wall','-Wextra','-Werror','-I',str(p),str(root/'test_uart_deadline.c'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True)
