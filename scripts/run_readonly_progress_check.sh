#!/usr/bin/env bash
# A single private native-memory QEMU test. No physical device arguments.
set -euo pipefail
cd "$(dirname "$(realpath "$0")")/.."
case "${1:-}" in
  good)
    tag=T23READONLYBAR1
    image=artifacts/phase21/retry-readonly-native-ui-v2/usb.raw
    marker=DONE
    ;;
  bad)
    tag=T23READONLYBARBAD1
    image=artifacts/phase21/retry-readonly-progress-short-v2/usb.raw
    marker=FAILED
    ;;
  *) exit 2 ;;
esac
exec python3 emulation/test_usb_maintenance.py \
  --tag "$tag" --seed artifacts/phase20/latest-car-seed.raw --usb "$image" \
  --audio-256 --native-memory --ram-mib 256 --boot-seconds 60 --stationary \
  --boot-info-frame 0f:94040000000000 --mcu-sw-release 05.e3.01 \
  --mcu-upg-config 01ffffffffffffffffffffffffffffff \
  --mcu-system-config 00ff01ffffffffffffffffffff003efa \
  --post-insert-seconds 1800 --wait-marker "$marker" \
  --usb-completion-log THEME_STATUS.TXT --usb-checkpoint-log THEME_STATUS.TXT \
  --completion-settle-seconds 15 --periodic-screenshot-seconds 5 \
  --acknowledge-completion
