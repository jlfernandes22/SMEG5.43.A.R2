#!/usr/bin/env bash
# One isolated native-memory installer test; never opens physical devices.
set -euo pipefail
cd "$(dirname "$(realpath "$0")")/.."
exec python3 emulation/test_usb_maintenance.py \
  --tag T24COMPLETEV12 --seed artifacts/phase20/latest-car-seed.raw \
  --usb artifacts/phase20/complete-stock-moving-progress-v12/usb.raw \
  --audio-256 --native-memory --ram-mib 256 --boot-seconds 60 --stationary \
  --boot-info-frame 0f:94040000000000 --mcu-sw-release 05.e3.01 \
  --mcu-upg-config 01ffffffffffffffffffffffffffffff \
  --mcu-system-config 00ff01ffffffffffffffffffff003efa \
  --post-insert-seconds 3000 --wait-marker DONE --abort-marker FAILED \
  --usb-completion-log THEME_STATUS.TXT --usb-checkpoint-log THEME_STATUS.TXT \
  --completion-settle-seconds 15 --periodic-screenshot-seconds 15 \
  --acknowledge-completion
