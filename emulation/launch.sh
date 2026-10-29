#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Render original guest GLES calls with Mesa while the MBX draw engine is
# incomplete. Set SMEG_SOFT_GLES=0 to exercise the native hardware path.
export SMEG_SOFT_GLES="${SMEG_SOFT_GLES:-1}"
export SMEG_GL_RENDERER="${SMEG_GL_RENDERER:-auto}"
# Hardware EGL when available; eight workers bound CPU usage on Mesa fallback.
export LP_NUM_THREADS="${LP_NUM_THREADS:-8}"
qemu_binary="$PWD/build/qemu/qemu-system-ppc"
if [[ ! -x "$qemu_binary" ]]; then
    echo 'QEMU build missing; run bash emulation/build.sh' >&2
    exit 1
fi
kernel_file="${SMEG_KERNEL:-$PWD/artifacts/phase2/package/SMEG_PLUS_UPG/BSP/SMEG_PLUS_512/vxWorks.bin}"
if [[ ! -f "$kernel_file" ]]; then
    echo "User-supplied kernel missing: $kernel_file" >&2
    exit 1
fi
mkdir -p artifacts/phase3
# A legacy linear flash window is optional. Complete interleaved NAND images
# use the smegnand backend directly and do not need a separate flash.raw.
flash_args=()
if [[ -n "${SMEG_FLASH:-}" ]]; then
    [[ -f "$SMEG_FLASH" ]] || { echo 'Missing optional linear flash image' >&2; exit 1; }
    flash_args=(-drive "if=none,id=smegflash,file=$SMEG_FLASH,format=raw,readonly=on")
fi
nand_args=()
nav_nand_default="$PWD/artifacts/phase3/nand-complete.raw"
nand_file="${SMEG_NAND:-$nav_nand_default}"
if [[ ! -f "$nand_file" ]]; then
    echo "Populated NAND image missing: $nand_file" >&2
    exit 1
fi
# Native board straps are derived from NAND capacity: 256/256 or 512/512.
# Changing RAM alone while retaining a 512-MiB NAND is not a 256-MiB test.
case "$(stat -c %s -- "$nand_file")" in
    276824064|553648128) ;; # 131072/262144 interleaved 2048+64-byte pages
    *) echo 'NAND must be a complete 256- or 512-MiB data image with 64-byte/page OOB' >&2
       exit 1 ;;
esac
nand_args=(-drive "if=none,id=smegnand,file=$nand_file,format=raw")
usb_args=()
if [[ -n "${SMEG_USB_MEDIA:-}" ]]; then
    [[ -f "$SMEG_USB_MEDIA" ]] || { echo 'Missing USB bench media image' >&2; exit 1; }
    export SMEG_USB_HOST=1
    # dosFs legitimately writes volume metadata on mount. Preserve the source
    # template and let each NAND case own a writable virtual USB disk.
    usb_work="${SMEG_USB_WORKING_MEDIA:-$(dirname "$nand_file")/usb-media.raw}"
    [[ "$(realpath -m "$usb_work")" != "$(realpath "$SMEG_USB_MEDIA")" ]] || {
        echo 'USB working copy must differ from source template' >&2; exit 1;
    }
    if [[ ! -e "$usb_work" ]]; then
        cp --reflink=auto -- "$SMEG_USB_MEDIA" "$usb_work"
        chmod u+w -- "$usb_work"
    fi
    [[ -f "$usb_work" && -w "$usb_work" ]] || { echo 'USB working image is not writable' >&2; exit 1; }
    usb_args=(-drive "if=none,id=benchmedia,file=$usb_work,format=raw")
    # Insertion experiments attach this existing backend later with QMP
    # device_add. Controller initialization is identical in both modes.
    if [[ "${SMEG_USB_HOTPLUG:-0}" != 1 ]]; then
        usb_args+=(-device usb-storage,id=benchusb,drive=benchmedia,removable=on)
    fi
fi
sd_args=()
if [[ -n "${SMEG_SD_MEDIA:-}" ]]; then
    [[ -f "$SMEG_SD_MEDIA" ]] || { echo 'Missing virtual SD template' >&2; exit 1; }
    sd_work="${SMEG_SD_WORKING_MEDIA:-$(dirname "$nand_file")/sd-card.raw}"
    [[ "$(realpath -m "$sd_work")" != "$(realpath "$SMEG_SD_MEDIA")" ]] || {
        echo 'SD working copy must differ from its protected template' >&2; exit 1;
    }
    if [[ ! -e "$sd_work" ]]; then
        cp --reflink=auto -- "$SMEG_SD_MEDIA" "$sd_work"
        chmod u+w -- "$sd_work"
    fi
    [[ -f "$sd_work" && -w "$sd_work" ]] || { echo 'SD working image is not writable' >&2; exit 1; }
    sd_args=(-drive "if=none,id=smeg_sd,file=$sd_work,format=raw")
fi
# This PPC32 guest cannot use x86 KVM or QEMU PPC64-only MTTCG.
exec "$qemu_binary" \
    -machine smeg-mpc5121e \
    -cpu e300c4 -accel tcg,thread=single -smp 1 -m "${SMEG_RAM_SIZE:-512M}" \
    -kernel "$kernel_file" \
    "${flash_args[@]}" \
    "${nand_args[@]}" \
    "${usb_args[@]}" \
    "${sd_args[@]}" \
    -display "${SMEG_DISPLAY:-none}" -serial "${SMEG_SERIAL:-mon:stdio}" -no-reboot \
    -d unimp,guest_errors -D "$PWD/artifacts/phase3/mmio.log" "$@"
