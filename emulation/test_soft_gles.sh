#!/bin/sh
# Genuine software renderer integration checks; requires desktop Mesa/EGL.
set -eu
# Deterministic headless pixel tests explicitly select the Mesa software ICD.
export SMEG_GL_RENDERER=software LIBGL_ALWAYS_SOFTWARE=1
if [ -r /usr/share/glvnd/egl_vendor.d/50_mesa.json ]; then
    export __EGL_VENDOR_LIBRARY_FILENAMES=/usr/share/glvnd/egl_vendor.d/50_mesa.json
fi
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build=$(mktemp -d /tmp/smeg-soft-gles-test.XXXXXX)
trap 'rm -rf "$build"' EXIT HUP INT TERM
cd "$root"
# pkg-config flags are deliberately shell-split into compiler arguments.
g++ -std=c++11 -O2 -Iemulation/powervr -c emulation/powervr/PVRTDecompress.cpp -o "$build/pvr.o"
g++ -std=c++11 -O2 -Iemulation/powervr -c emulation/powervr/smeg_pvrtc.cpp -o "$build/adapter.o"
cc -O2 -Wall -Wextra -Werror -Iemulation $(pkg-config --cflags egl gl libffi glib-2.0) -c emulation/test_soft_gles.c -o "$build/test.o"
g++ "$build/test.o" "$build/pvr.o" "$build/adapter.o" $(pkg-config --libs egl gl libffi glib-2.0) -ldl -o "$build/test"
"$build/test"
