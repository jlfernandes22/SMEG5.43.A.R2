#!/usr/bin/env bash
# Visible local authentication fallback; no passwords pass through agent tools.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "${1:-}" != --inside ]]; then
    exec alacritty --title 'SMEG Bluetooth test — local authentication' \
        -e bash "$PWD/emulation/launch_hci_desktop.sh" --inside "${@}"
fi
printf '%s\n' \
    'SMEG isolated Bluetooth test (no physical car access).' \
    'The laptop radio is leased to the test for at most five minutes.' \
    'The phone disconnects temporarily; adapter power and links restore afterward.' \
    'Enter your laptop password at the sudo prompt below; never send it in chat.'
export SMEG_CASE=hci_compat
export SMEG_HCI_AUTH=sudo
export SMEG_HCI_LIVE_MODE=infineon-live
export SMEG_DISPLAY="${SMEG_DISPLAY:-none}"
set +e
if [[ "${2:-}" == --diagnostic ]]; then
    printf '\nController diagnostic only: name lookup, no pairing or key changes.\n'
    sudo /usr/bin/python3 "$PWD/emulation/hci_radio_lease.py" \
        --case "$SMEG_CASE" --mode diagnostic --seconds 60
else
    iterations=1
    [[ "${2:-}" == --batch ]] && iterations=4
    request="$PWD/artifacts/phase4/runs/$SMEG_CASE/desktop-next.request"
    state="$PWD/artifacts/phase4/runs/$SMEG_CASE/desktop-session.state"
    rm -f "$request"
    trap 'rm -f "$request" "$state"' EXIT
    for ((iteration=1;iteration<=iterations;iteration++)); do
        printf 'running %s %s\n' "$$" "$iteration" > "$state"
        bash emulation/launch_hci_live.sh
        status=$?
        [[ "$iterations" == 1 || "$status" == 130 || "$status" == 143 ]] && break
        printf '\nRadio restored. Waiting up to three minutes for the next test request.\n'
        printf 'waiting %s %s\n' "$$" "$iteration" > "$state"
        ready=0
        for ((n=0;n<900;n++)); do
            if [[ -f "$request" ]]; then ready=1; break; fi
            sleep .2
        done
        [[ "$ready" == 1 ]] || break
        action=$(cat "$request")
        rm -f "$request"
        [[ "$action" == start ]] || break
    done
    exit "$status"
fi
status=$?
printf '\nBluetooth test finished (exit %d). Press Enter to close.\n' "$status"
read -r _
exit "$status"
