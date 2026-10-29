#!/usr/bin/env bash
# Open the original SMEG application in a native laptop window.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p artifacts/phase3
if [[ -z "${SMEG_NAND:-}" ]]; then
    ui_nand="$PWD/artifacts/phase3/nand-interactive.raw"
    if [[ ! -f "$ui_nand" ]]; then
        [[ -f artifacts/phase3/nand-complete.raw ]] || {
            echo 'Prepared NAND missing; see docs/EMULATION.md' >&2
            exit 1
        }
        cp --reflink=auto artifacts/phase3/nand-complete.raw "$ui_nand"
    fi
    export SMEG_NAND="$ui_nand"
fi
export SMEG_SOFT_GLES="${SMEG_SOFT_GLES:-1}"
# Accelerate verified native application RAM-copy/fill exports; retain kernel
# and MMIO execution. Set SMEG_FAST_MEM=0 to compare native instructions.
export SMEG_FAST_MEM="${SMEG_FAST_MEM:-1}"
# Prefer the validated Mesa software path; auto is available for host-specific
# GPU comparisons after checking idle/readback behavior on that driver.
export SMEG_GL_RENDERER="${SMEG_GL_RENDERER:-software}"
export SMEG_DISPLAY="${SMEG_DISPLAY:-gtk,zoom-to-fit=on}"
export SMEG_SERIAL="${SMEG_SERIAL:-file:$PWD/artifacts/phase3/interactive.serial.log}"
window_log="${SMEG_WINDOW_LOG:-$PWD/artifacts/phase3/interactive.window.log}"
control_prefix="${SMEG_CONTROL_PREFIX:-$PWD/artifacts/phase3/interactive}"
mkdir -p "$(dirname "$window_log")" "$(dirname "$control_prefix")"
exec > "$window_log" 2>&1
if [[ "${SMEG_PIN_THREADS:-0}" == 1 ]]; then
    # Opt in only after selecting CPU IDs suitable for this host's topology.
    # Wait for GL workers before pinning; workers must not inherit one CPU.
    python3 emulation/tune_ui_threads.py --pid "$$" --once \
        --socket "$control_prefix.qmp" \
        --renderer-ready-log "$window_log" \
        --output "$control_prefix.affinity.json" \
        > "$control_prefix.affinity.log" 2>&1 &
fi
exec bash emulation/launch.sh \
    -name 'SMEG+ 5.43.A.R2' \
    -monitor "unix:$control_prefix.monitor,server=on,wait=off" \
    -qmp "unix:$control_prefix.qmp,server=on,wait=off" \
    -gdb "unix:$control_prefix.gdb,server=on,wait=off" \
    -D "$PWD/artifacts/phase3/interactive.qemu.log" "$@"
