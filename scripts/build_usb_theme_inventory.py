#!/usr/bin/env python3
"""Build an isolated QEMU-only read-only theme-inventory native USB probe.

Only native read APIs are called; no settings are requested. No replacement database or firmware payload.
No block devices, physical USB writes, VM operations or RAM policy patches.
CRC metadata is not a vendor signature or physical deployment approval.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile

from smeg_db_inf import crc16

ROOT = Path(__file__).resolve().parents[1]
ALLOWED = ROOT / "artifacts/phase19/theme-inventory"
SYMBOLS = ["ReadBigHarmonyPreHeader", "ReadBigHarmonyBigHeader", "ReadBigHarmonyHeader"]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ALLOWED) or output.suffix != ".raw" or output.exists():
        parser.error("A new regular .raw image under artifacts/phase19/theme-inventory is required")
    output.parent.mkdir(parents=True, exist_ok=True)
    generated = [output.with_suffix(".json"), output.parent / "usb_warmlight_api_fingerprints.h",
                 output.parent / "theme_inventory.out"]
    if any(path.exists() for path in generated):
        parser.error("Generated build artifacts already exist; choose a new empty build directory")
    symbols_path = ROOT / "artifacts/phase2/filesystems/AUDIO_BT_256/system/Application/PKG/symbols_bsp.txt.gz"
    symbol_lines = gzip.decompress(symbols_path.read_bytes()).decode("latin1").splitlines()
    lookup = {parts[2]: int(parts[0], 16) for line in symbol_lines
              if len(parts := line.split()) == 3}
    app_path = ROOT / "artifacts/phase2/package/SMEG_PLUS_UPG/BSP/SMEG_PLUS_256/vxWorks.bin"
    image = app_path.read_bytes()
    checks = []
    for name in SYMBOLS:
        address = lookup[name]
        raw = image[address - 0x200000:address - 0x200000 + 64]
        if len(raw) != 64:
            raise ValueError("Short native API fingerprint")
        value = 2166136261
        for byte in raw:
            value = ((value ^ byte) * 16777619) & 0xffffffff
        checks.append({"symbol": name, "address": address, "bytes": 64, "fnv1a": value})
    generated[1].write_text(
        "struct WarmApiCheck {unsigned int address,bytes,hash;};\n"
        "static const struct WarmApiCheck warm_api_checks[] = {\n" +
        "\n".join("    {0x%xu,64,0x%xu}," % (row["address"], row["fnv1a"]) for row in checks) + "\n};\n")
    source = ROOT / "emulation/usb_theme_inventory_readonly.c"
    compile_command = ["clang", "--target=powerpc-unknown-linux-gnu", "-mbig-endian", "-m32",
                       "-mlongcall", "-ffreestanding", "-fno-pic", "-fno-stack-protector",
                       "-fno-unwind-tables", "-fno-asynchronous-unwind-tables", "-msoft-float",
                       "-I", str(output.parent), "-I", str(ROOT / "emulation"),
                       "-O2", "-Wall", "-Wextra", "-Werror", "-c", str(source), "-o", str(generated[2])]
    subprocess.run(compile_command, check=True)
    payload = generated[2].read_bytes()
    if payload[:6] != b"\x7fELF\x01\x02" or struct.unpack_from(">H", payload, 18)[0] != 20:
        raise ValueError("Expected PPC32 big-endian ELF")
    basename = "theme_inventory.out"
    body = (f"{crc16(payload):04x}\r\nVER:SMEG5.43.A.R2\r\nTYPE:RELOCABLE\r\nID:0\r\n"
            f"COMPRESSED:NO\r\nSIZE:{len(payload)}\r\nENTRY:YES\r\n").encode()
    doctor = ("0000\r\nACTION:TemporaryBootRom\r\n"
              "LOAD_AND_EXECUTE:/bd0/FLYING/theme_inventory.out\r\n").encode()
    files = {"FLYING/" + basename: payload,
             "FLYING/" + basename + ".inf": f"{crc16(body):04x}".encode() + body,
             "FLYING/doctor_smeg_plus_i.inf": f"{crc16(doctor):04x}".encode() + doctor}

    def run(*command):
        return subprocess.run(command, check=True, capture_output=True,
                              env=dict(os.environ, MTOOLS_SKIP_CHECK="1"))

    offset, size = 1048576, 128 * 1024 * 1024
    with tempfile.TemporaryDirectory(prefix="smeg-warmlight-usb-") as tmp_name:
        tmp = Path(tmp_name)
        partition = tmp / "partition.fat"
        with partition.open("xb") as handle:
            handle.truncate(size)
        run("mkfs.vfat", "-F", "32", "-n", "QEMU_INV", str(partition))
        mbr = bytearray(512)
        mbr[446:462] = struct.pack("<B3sB3sII", 0, b"\xfe\xff\xff", 0x0c,
                                   b"\xfe\xff\xff", offset // 512, size // 512)
        mbr[510:512] = b"\x55\xaa"
        with output.open("xb") as handle:
            handle.write(mbr)
            handle.seek(offset)
            with partition.open("rb") as src:
                while chunk := src.read(1024 * 1024):
                    handle.write(chunk)
        spec = str(output) + "@@" + str(offset)
        run("mmd", "-i", spec, "::/FLYING")
        for index, (name, data) in enumerate(files.items()):
            source_file, readback = tmp / str(index), tmp / ("readback" + str(index))
            source_file.write_bytes(data)
            run("mcopy", "-i", spec, str(source_file), "::/" + name)
            run("mcopy", "-i", spec, "::/" + name, str(readback))
            if readback.read_bytes() != data:
                raise ValueError("Virtual FAT readback mismatch")
    metadata = {
        "emulator_only": True, "physical_car_approved": False, "physical_device_access": False,
        "image": str(output), "image_sha256": sha(output.read_bytes()),
        "partition": {"offset": offset, "bytes": size, "filesystem": "FAT32"},
        "entry": "smeg_usb_readonly_backup", "supported_profile": "AUDIO_BT_256_5.43",
        "read_only_inventory": {"banks": [1, 2, 3, 4, 5, 6], "maximum_entries_per_bank": 9, "configuration_setters": False, "flash_writers": False},
        "backup_before_set": True, "original_up_config_pair_readback_before_set": False,
        "no_configuration_requests": True, "no_database_replacement": True, "no_firmware_or_theme_resources": True,
        "no_ram_policy_patch": True, "no_automatic_reboot": True,
        "checksum_is_not_vendor_signature": True,
        "build_BSP_sha256": sha(image), "source_sha256": sha(source.read_bytes()),
        "backup_source_sha256": sha((ROOT / "emulation/usb_backup_readonly.c").read_bytes()),
        "compile_command": compile_command, "api_checks": checks,
        "files": [{"path": name, "bytes": len(data), "sha256": sha(data)} for name, data in files.items()],
    }
    generated[0].write_text(json.dumps(metadata, indent=2) + "\n")
    print(json.dumps({"image": str(output), "image_sha256": metadata["image_sha256"],
                      "metadata": str(generated[0]), "module_bytes": len(payload),
                      "emulator_only": True, "physical_car_approved": False}))


if __name__ == "__main__":
    main()
