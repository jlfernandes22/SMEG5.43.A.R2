#!/usr/bin/env bash
# Optional offline Apps replacement in a separate emulator profile.
set -euo pipefail
cd "$(dirname "$0")/.."
export SMEG_CASE="${SMEG_CASE:-local_apps}"
export SMEG_NAND="$PWD/artifacts/phase4/runs/$SMEG_CASE/nand.raw"
[[ -f "$SMEG_NAND" ]] || {
    echo 'Prepare a separate NAND with emulation/prepare_local_apps.py first.' >&2
    exit 1
}
exec bash emulation/launch_features.sh -name 'SMEG+ local offline Apps sandbox' "$@"
