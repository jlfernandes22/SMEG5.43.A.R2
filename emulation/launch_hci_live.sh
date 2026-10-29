#!/usr/bin/env bash
# Temporary exclusive physical-radio test in an isolated SMEG sandbox.
set -euo pipefail
cd "$(dirname "$0")/.."
export SMEG_CASE="${SMEG_CASE:-hci_live}"
[[ "$SMEG_CASE" =~ ^[a-z0-9_-]+$ ]] || exit 1
bridge_mode="${SMEG_HCI_LIVE_MODE:-infineon-live}"
[[ "$bridge_mode" == live || "$bridge_mode" == infineon-live ]] || exit 1
case_dir="$PWD/artifacts/phase4/runs/$SMEG_CASE"
[[ -f "$case_dir/nand.raw" ]] || { echo 'Prepare a stopped NAND copy for hci_live first.' >&2; exit 1; }
[[ ! -e "$case_dir/hci.sock" ]] || { echo 'Existing HCI socket: another test may be running.' >&2; exit 1; }
lease_seconds="${SMEG_HCI_LEASE_SECONDS:-300}"
front_panel="${SMEG_HCI_FRONT_PANEL:-0}"
if [[ -f "$case_dir/interactive-session.enable" ]]; then
    lease_seconds=900
    front_panel=1
fi
lease_args=(--case "$SMEG_CASE" --mode "$bridge_mode" --seconds "$lease_seconds")
if [[ -n "${SMEG_HCI_PEER_ADDRESS:-}" ]]; then
    lease_args+=(--peer "$SMEG_HCI_PEER_ADDRESS")
fi
if [[ "${SMEG_HCI_REUSE_HOST_BOND:-0}" == 1 || -f "$case_dir/reuse-host-bond.enable" ]]; then
    lease_args+=(--reuse-host-bond)
fi
python3 emulation/hci_radio_lease.py --plan "${lease_args[@]}"
case "${SMEG_HCI_AUTH:-pkexec}" in
    pkexec) auth_command=(pkexec) ;;
    sudo)
        [[ -t 0 ]] || { echo 'sudo authentication requires a visible terminal.' >&2; exit 1; }
        # Authenticate in the foreground, outside the capture log. Password
        # entry stays in the user's terminal and is never collected by tools.
        sudo -v
        auth_command=(sudo -n)
        ;;
    *) echo 'SMEG_HCI_AUTH must be pkexec or sudo.' >&2; exit 1 ;;
esac
"${auth_command[@]}" /usr/bin/python3 "$PWD/emulation/hci_radio_lease.py" "${lease_args[@]}" > "$case_dir/radio-lease.log" 2>&1 &
lease_pid=$!
# The privileged lease has a fixed deadline and restores the host adapter.
for ((n=0;n<1200;n++)); do
    [[ -S "$case_dir/hci.sock" ]] && break
    ps -p "$lease_pid" > /dev/null || { cat "$case_dir/radio-lease.log"; exit 1; }
    sleep .1
done
[[ -S "$case_dir/hci.sock" ]] || { echo 'Authentication/lease did not become ready.' >&2; exit 1; }
# When QEMU closes H4, the bridge exits and the parent restores BlueZ. If the
# lease expires first, close only this test window rather than leaving a GUI
# that silently lost its radio backend.
SMEG_FRONT_PANEL="$front_panel" bash emulation/launch_features.sh \
    -name 'SMEG HCI live radio test (temporary)' \
    -chardev "socket,id=smeg-bt,path=$case_dir/hci.sock" "$@" &
emulator_pid=$!
cleanup_test() {
    trap - EXIT INT TERM
    if kill -0 "$emulator_pid" 2>/dev/null; then
        python3 emulation/ui_control.py --socket "$case_dir/control.qmp" --quit >/dev/null 2>&1 || \
            kill "$emulator_pid" 2>/dev/null || true
    fi
    wait "$emulator_pid" || true
    wait "$lease_pid" || true
}
trap cleanup_test EXIT INT TERM
while kill -0 "$emulator_pid" 2>/dev/null && ps -p "$lease_pid" > /dev/null; do
    sleep .2
done
