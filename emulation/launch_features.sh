#!/usr/bin/env bash
# Original SMEG application with tested sandbox options and simulated ECUs.
set -euo pipefail
cd "$(dirname "$0")/.."
export SMEG_CASE="${SMEG_CASE:-features}"
[[ "$SMEG_CASE" =~ ^[a-z0-9_-]+$ ]] || { echo 'Invalid sandbox case name' >&2; exit 1; }
case_dir="$PWD/artifacts/phase4/runs/$SMEG_CASE"
export SMEG_NAND="${SMEG_NAND:-$case_dir/nand.raw}"
export SMEG_ISOLATE_CONTROLS=1
# Reproduce the tested desktop profiles without pinning separate instances to
# the same two host cores. Explicit affinity remains an opt-in comparison.
export SMEG_PIN_THREADS="${SMEG_PIN_THREADS:-0}"
export LP_NUM_THREADS="${LP_NUM_THREADS:-4}"
export SMEG_BENCH_ECO_OFF=1
export SMEG_BENCH_VEHICLE=1
export TZ="${TZ:-Europe/Lisbon}"
export SMEG_BENCH_BODY_CONFIG=1
export SMEG_BENCH_ECU=1
export SMEG_BENCH_KEY_PROFILE=1
export SMEG_USB_MEDIA="${SMEG_USB_MEDIA:-$PWD/artifacts/phase4/media-test.raw}"
# Empty real FAT32 SD enables native navigation startup; contains no maps.
# An explicitly empty variable disables the optional SD fixture.
export SMEG_SD_MEDIA="${SMEG_SD_MEDIA-$PWD/artifacts/phase4/sd-mapless.raw}"
if [[ "${SMEG_FRONT_PANEL:-1}" == 1 && "${SMEG_DISPLAY:-gtk}" != none* ]]; then
    panel_dir="$case_dir"
    mkdir -p "$panel_dir"
    panel_args=()
    if [[ "${SMEG_ASR_DEMO:-0}" == 1 ]]; then panel_args+=(--asr-demo); fi
    python3 emulation/front_panel.py --socket "$panel_dir/control.qmp" \
        --parent-pid "$$" "${panel_args[@]}" > "$panel_dir/front-panel.log" 2>&1 &
fi
exec bash emulation/launch_factory_db.sh -name 'SMEG+ features / simulated vehicle' \
    -rtc base=localtime,clock=host -action reboot=reset "$@"
