#!/usr/bin/env bash
# Private USB-free reboot of a completed installer test; no physical devices.
set -euo pipefail
cd "$(dirname "$(realpath "$0")")/.."
python3 - <<'PY'
from pathlib import Path
import json, subprocess
run = Path('artifacts/phase8/usb-maintenance/runs/T24COMPLETEV12')
result = json.loads((run / 'result.json').read_text())
assert result['returncode'] == 0 and result['wait_marker_seen']
log = subprocess.check_output(['mtype', '-i', str(run/'usb.raw')+'@@1048576',
                               '::/SMEG_BACKUP/complete-themes.txt'], text=True)
assert 'COMPLETE_THEMES_RESULT status=0\n' in log
PY
exec python3 emulation/test_all_themes.py \
  --nand artifacts/phase8/usb-maintenance/runs/T24COMPLETEV12/nand.raw \
  --tag P20FINALV12COLD --seconds 900 --native-memory --ram-mib 256 \
  --boot-info-frame 0f:94040000000000 --mcu-sw-release 05.e3.01 \
  --mcu-upg-config 01ffffffffffffffffffffffffffffff \
  --mcu-system-config 00ff01ffffffffffffffffffff003efa
