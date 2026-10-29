#!/usr/bin/env bash
# Isolated factory-database UI experiment. No physical device access.
set -euo pipefail
cd "$(dirname "$0")/.."
export SMEG_NAND="${SMEG_NAND:-$PWD/artifacts/phase3/nand-ui.raw}"
case_dir="$PWD/artifacts/phase4"
if [[ -n "${SMEG_CASE:-}" ]]; then
    [[ "$SMEG_CASE" =~ ^[a-z0-9_-]+$ ]] || { echo 'Invalid sandbox case name' >&2; exit 1; }
    case_dir="$PWD/artifacts/phase4/runs/$SMEG_CASE"
fi
mkdir -p "$case_dir"
if [[ "${SMEG_ISOLATE_CONTROLS:-0}" == 1 ]]; then
    export SMEG_CONTROL_PREFIX="$case_dir/control"
fi
export SMEG_SERIAL="file:$case_dir/factory_db.serial.log"
export SMEG_WINDOW_LOG="$case_dir/factory_db.window.log"
[[ -f "$SMEG_NAND" ]] || {
    echo 'Missing injected sandbox image; run prepare_factory_flags.py and inject_volume.py first.' >&2
    exit 1
}
exec bash emulation/launch_ui.sh \
    -name 'SMEG+ factory database sandbox' \
    -D "$case_dir/factory_db.qemu.log" "$@"
