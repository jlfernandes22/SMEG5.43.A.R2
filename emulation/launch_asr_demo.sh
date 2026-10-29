#!/usr/bin/env bash
# Optional original Grip Control artwork, using a separate tested SQUARE NAND.
# This profile is not the all-theme stable profile. REFLEX/REDLINE/ESSENTIEL
# contain original DOTE placeholders for this optional screen.
set -euo pipefail
cd "$(dirname "$0")/.."
export SMEG_CASE="${SMEG_CASE:-asr_demo}"
export SMEG_ASR_DEMO=1
[[ "$SMEG_CASE" =~ ^[a-z0-9_-]+$ ]] || { echo 'Invalid sandbox case name' >&2; exit 1; }
case_dir="$PWD/artifacts/phase4/runs/$SMEG_CASE"
seed="$PWD/artifacts/phase4/runs/asr_demo_seed/nand.raw"
mkdir -p "$case_dir"
if [[ -z "${SMEG_NAND:-}" ]]; then
    export SMEG_NAND="$case_dir/nand.raw"
    if [[ ! -e "$SMEG_NAND" ]]; then
        [[ -f "$seed" ]] || { echo 'Missing tested ASR demo NAND seed' >&2; exit 1; }
        cp --reflink=auto -- "$seed" "$SMEG_NAND"
        chmod u+w -- "$SMEG_NAND"
    fi
fi
[[ "$(realpath "$SMEG_NAND")" != "$(realpath "$seed")" ]] || {
    echo 'ASR demo must run a separate copy of its tested seed' >&2; exit 1;
}
exec bash emulation/launch_features.sh -name 'SMEG+ Grip Control demo / SQUARE' "$@"
