#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 emulation/install_qemu_machine.py sources/qemu
python3 emulation/patch_qemu_rfi.py sources/qemu
mkdir -p build/qemu
cd build/qemu
# libnfs is unnecessary for this board; QEMU9.2 predates the installed API.
../../sources/qemu/configure \
    --target-list=ppc-softmmu --disable-docs --disable-werror \
    --enable-gtk --disable-sdl --disable-vnc --disable-opengl \
    --disable-curses --disable-slirp --disable-capstone --disable-libnfs
ninja -j "${SMEG_BUILD_JOBS:-8}" qemu-system-ppc
