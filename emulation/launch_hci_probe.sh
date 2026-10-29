#!/usr/bin/env bash
# Isolated native SMEG + no-radio HCI initialization probe.
set -euo pipefail
cd "$(dirname "$0")/.."
export SMEG_CASE="${SMEG_CASE:-hci_probe}"
probe_mode="${SMEG_HCI_PROBE_MODE:-probe}"
[[ "$probe_mode" == probe || "$probe_mode" == infineon-probe ]] || exit 1
[[ "$SMEG_CASE" =~ ^[a-z0-9_-]+$ ]] || exit 1
case_dir="$PWD/artifacts/phase4/runs/$SMEG_CASE"
mkdir -p "$case_dir"
[[ -f "$case_dir/nand.raw" ]] || { echo 'Copy a stopped sandbox NAND to this case first.' >&2; exit 1; }
bt_socket="$case_dir/hci.sock"
[[ ! -e "$bt_socket" ]] || { echo 'HCI socket already exists; refusing to replace it.' >&2; exit 1; }
python3 emulation/hci_bridge.py --mode "$probe_mode" --socket "$bt_socket" --log "$case_dir/hci.jsonl" &
bridge_pid=$!
trap 'kill "$bridge_pid" 2>/dev/null || true; wait "$bridge_pid" 2>/dev/null || true' EXIT INT TERM
for ((n=0;n<100;n++)); do
    [[ -S "$bt_socket" ]] && break
    kill -0 "$bridge_pid" 2>/dev/null || exit 1
    sleep .02
done
bash emulation/launch_features.sh -chardev "socket,id=smeg-bt,path=$bt_socket" "$@"
