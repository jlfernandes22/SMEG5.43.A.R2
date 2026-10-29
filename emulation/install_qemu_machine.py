#!/usr/bin/env python3
"""Install the experimental board into a user-selected QEMU source tree."""
from pathlib import Path
import argparse
import shutil
import subprocess
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("qemu_source", type=Path)
args = parser.parse_args()
root = args.qemu_source.resolve()
meson = root / "hw/ppc/meson.build"
if not (root / "target/ppc/cpu.h").is_file() or not meson.is_file():
    parser.error("Expected a QEMU source tree with the PowerPC target")
source = Path(__file__).with_name("mpc5121e_smeg.c")
shutil.copyfile(source, root / "hw/ppc/mpc5121e_smeg.c")
shutil.copyfile(source.with_name("smeg_nfc.h"), root / "hw/ppc/smeg_nfc.h")
shutil.copyfile(source.with_name("smeg_mcu_peer.h"), root / "hw/ppc/smeg_mcu_peer.h")
shutil.copyfile(source.with_name("smeg_bench_environment.h"), root / "hw/ppc/smeg_bench_environment.h")
shutil.copyfile(source.with_name("smeg_bench_ecu.h"), root / "hw/ppc/smeg_bench_ecu.h")
shutil.copyfile(source.with_name("smeg_bench_alert.h"), root / "hw/ppc/smeg_bench_alert.h")
shutil.copyfile(source.with_name("smeg_bench_led.h"), root / "hw/ppc/smeg_bench_led.h")
shutil.copyfile(source.with_name("smeg_dma_copy.h"), root / "hw/ppc/smeg_dma_copy.h")
shutil.copyfile(source.with_name("smeg_hci_uart.h"), root / "hw/ppc/smeg_hci_uart.h")
shutil.copyfile(source.with_name("smeg_sdhc.h"), root / "hw/ppc/smeg_sdhc.h")
shutil.copyfile(source.with_name("smeg_diu.h"), root / "hw/ppc/smeg_diu.h")
for name in ("smeg_soft_gles.c", "smeg_gles_symbols.inc", "smeg_gles_upgrade_aliases.inc"):
    shutil.copyfile(source.with_name(name), root / "hw/ppc" / name)
shutil.copytree(source.with_name("powervr"), root / "hw/ppc/powervr",
                dirs_exist_ok=True)
top_meson = root / "meson.build"
top_text = top_meson.read_text()
cpp_old = "if host_os == 'windows' and add_languages('cpp', required: false, native: false)"
cpp_new = "if (host_os == 'windows' or 'ppc-softmmu' in target_dirs) and add_languages('cpp', required: true, native: false)"
if cpp_old in top_text:
    top_meson.write_text(top_text.replace(cpp_old, cpp_new))
elif cpp_new not in top_text:
    parser.error("QEMU C++ language setup changed; integration needs review")
shutil.copyfile(source.with_name("smeg_soft_gles.h"),
                root / "include/hw/ppc/smeg_soft_gles.h")
old_line = "ppc_ss.add(files('mpc5121e_smeg.c'))\n"
previous_line = ("ppc_ss.add(files('mpc5121e_smeg.c', 'smeg_soft_gles.c'))\n"
        "ppc_ss.add(dependency('egl'), dependency('gl'), dependency('libffi'), cc.find_library('dl'))\n")
line = ("ppc_ss.add(files('mpc5121e_smeg.c', 'smeg_soft_gles.c',\n"
        "  'powervr/smeg_pvrtc.cpp', 'powervr/PVRTDecompress.cpp'))\n"
        "ppc_ss.add(dependency('egl'), dependency('gl'), dependency('libffi'), cc.find_library('dl'))\n")
text = meson.read_text()
if previous_line in text:
    meson.write_text(text.replace(previous_line, line))
elif old_line in text:
    meson.write_text(text.replace(old_line, line))
elif line not in text:
    marker = "hw_arch += {'ppc': ppc_ss}"
    if marker not in text:
        parser.error("QEMU PowerPC meson structure changed; integration needs review")
    meson.write_text(text.replace(marker, line + "\n" + marker))
subprocess.run([sys.executable, str(source.with_name("patch_qemu_gles.py")),
                str(root)], check=True)
subprocess.run([sys.executable, str(source.with_name("patch_qemu_ehci.py")),
                str(root)], check=True)
print(f"Installed experimental smeg-mpc5121e machine into {root}")
