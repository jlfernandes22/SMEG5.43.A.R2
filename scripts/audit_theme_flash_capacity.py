#!/usr/bin/env python3
"""Check final theme sizes against the recovered Audio bank boundaries.

Reads regular workspace files only. Does not identify the physical NAND,
measure its bad blocks, or establish the driver's physical remapping capacity.
"""
import hashlib
import json
from pathlib import Path
import struct
import zlib

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "artifacts/phase15/candidate-allthemes-v7/SMEG_PLUS_UPG"
OUT = ROOT / "artifacts/phase16/theme-flash-capacity.json"
PAGE = 2048
ERASE_BLOCK = PAGE * 64
BANKS = {4: (0x2DC0000, 0x4F60000), 5: (0x4F60000, 0x7100000)}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    if OUT.exists():
        raise ValueError("Preserve existing audit output")
    manifest_path = ROOT / "artifacts/phase15/theme-assets/all-eight-menu-colour-style-v7/manifest.json"
    manifest = json.loads(manifest_path.read_text())
    source_files = {r["path"]: r for r in manifest["files"]}
    results = []
    for group, (start, end) in BANKS.items():
        relative = f"HARMONY/BigHarmony_{group}/BIG_HARMONY.bin"
        path = PACKAGE / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError("Regular candidate file required")
        data = path.read_bytes()
        expected = source_files[relative]
        if sha(data) != expected["SHA256"] or len(data) != expected["bytes"]:
            raise ValueError("Final asset manifest mismatch")
        if not data.startswith(b"BIGHARMONY") or len(data) > end - start:
            raise ValueError("Bank header or capacity mismatch")
        count = struct.unpack_from(">I", data, PAGE + 32)[0]
        if count != 4 or PAGE + 36 + 216 * count > 2 * PAGE:
            raise ValueError("Unexpected entry table")
        entries = []
        ranges = []
        for index in range(count):
            offset = PAGE + 36 + 216 * index
            position, uid, page, size, crc = struct.unpack_from(">5I", data, offset + 196)
            if position != index or page < 2:
                raise ValueError("Entry index/page mismatch")
            body = data[page * PAGE:page * PAGE + size]
            if len(body) != size or zlib.crc32(body) != crc:
                raise ValueError("Entry body checksum mismatch")
            expanded = zlib.decompress(body[4:])
            if len(expanded) != struct.unpack_from(">I", body)[0]:
                raise ValueError("Entry expansion size mismatch")
            ranges.append((page * PAGE, page * PAGE + size))
            entries.append({"index": index, "universal_id": uid,
                            "payload_page": page, "compressed_bytes": size,
                            "expanded_bytes": len(expanded),
                            "expanded_sha256": sha(expanded)})
        if any(a[1] > b[0] for a, b in zip(sorted(ranges), sorted(ranges)[1:])):
            raise ValueError("Overlapping resource entries")
        rounded_bytes = ((len(data) + ERASE_BLOCK - 1) // ERASE_BLOCK) * ERASE_BLOCK
        results.append({"bank": group, "file": relative, "sha256": sha(data),
                        "logical_start": hex(start), "logical_end_exclusive": hex(end),
                        "bank_capacity_bytes": end - start, "payload_bytes": len(data),
                        "payload_rounded_to_model_erase_blocks": rounded_bytes,
                        "unused_model_bytes": end - start - len(data),
                        "unused_whole_model_erase_blocks": (end - start - rounded_bytes) // ERASE_BLOCK,
                        "entries": entries})
    report = {
        "scope": "Offline logical bank capacity and stream integrity, not physical bad-block tolerance",
        "manifest_sha256": sha(manifest_path.read_bytes()),
        "model_page_bytes": PAGE, "model_erase_block_bytes": ERASE_BLOCK,
        "banks": results,
        "logical_payloads_fit": True,
        "unused_blocks_are_not_a_verified_physical_bad_block_budget": True,
        "physical_NAND_geometry_bad_blocks_health_and_mapping_measured": False,
        "physical_devices_accessed": False,
        "package_modified": False,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"report": str(OUT.relative_to(ROOT)), "logical_payloads_fit": True,
                      "unused_whole_model_erase_blocks": {
                          r["bank"]: r["unused_whole_model_erase_blocks"] for r in results},
                      "physical_bad_block_tolerance_verified": False}))


if __name__ == "__main__":
    main()
