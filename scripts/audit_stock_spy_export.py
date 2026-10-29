#!/usr/bin/env python3
"""Inventory a copied stock SPY export and recover included SQLite files safely.

Reads host files only. Archive names are never used as output paths. No firmware,
USB device, vehicle, or source archive is changed. This does not reconstruct
missing databases from logs or claim a complete backup from a partial capture.
"""
import argparse
import gzip
import hashlib
import io
import json
import re
import sqlite3
import tarfile
from pathlib import Path

LIMIT = 64 * 1024 * 1024
TARGETS = {"up_config.sqlite", "config_options.sqlite", "up_common.sqlite", "up_user.sqlite"}


def parameter_snapshot(data, location):
    """Parse stock ShowStatus output, preserving dump groups and incomplete rows.

    These are runtime parameter observations, not reconstructed SQLite files.
    Interleaved UART output can damage individual lines; never guess those values.
    """
    text = data.replace(b"\0", b"").decode("latin1")
    groups, options, hardware, bluetooth = [], {}, {}, {}
    for line in text.splitlines():
        header = re.search(r"CMMUPKeys::ShowStatus\s*\((\d+) keys\)", line)
        if header:
            groups.append({"declared_keys": int(header[1]), "entries": []})
            continue
        option = re.match(r"\s*(SW_OPTION_[A-Z0-9_]+)\s*:\s*(true|false)\s*\(([01])\)", line)
        if option and (option[2] == "true") == bool(int(option[3])):
            options[option[1]] = int(option[3])
        hw = re.match(r"\s*(HW_FLAG_[A-Z0-9_]+)\s*:\s*(true|false)\s*\(([01])\)", line)
        if hw and (hw[2] == "true") == bool(int(hw[3])):
            hardware[hw[1]] = int(hw[3])
        key = re.fullmatch(r"\s*([A-Za-z0-9_.-]+)\.(\d+)\s+<([^>]+)>\s*:\s*(.*?)\s*", line)
        if key and groups and "BMFP_SPI" not in key[4]:
            value = key[4]
            if key[3] == "bool":
                if value not in ("true", "false"): continue
                value = value == "true"
            elif key[3] in ("int", "uint"):
                try: value = int(value, 0) if value.startswith(("0x", "-0x")) else int(value)
                except ValueError: continue
            groups[-1]["entries"].append({"key": key[1], "index": int(key[2]), "type": key[3], "value": value})
        flag = re.search(r"\b(m_force_no_(?:dun|pan)_management)\s*(?:is|:)\s*(true|false)\b", line)
        if flag: bluetooth[flag[1]] = flag[2] == "true"
        state = re.match(r"\s*(PAN|DUN):STATE:([A-Z_]+)", line)
        if state: bluetooth[state[1] + "_state"] = state[2]
        # Connection traces also report later transitions in a combined line.
        # A startup NOT_CONFIGURED snapshot must not hide CONFIGURED later on.
        combined = re.search(r"HFP:[A-Z_]+/A2DP:[A-Z_]+/DUN:([A-Z_]+)/PAN:([A-Z_]+)", line)
        if combined:
            states = {"DUN_state": combined[1], "PAN_state": combined[2]}
            bluetooth.update(states)
            timeline = bluetooth.setdefault("observed_state_changes", [])
            if not timeline or timeline[-1] != states:
                timeline.append(states)
        profile = re.match(r"\s*(m_(?:requested_)?internet_profile)\s*:\s*(BCM_BT_CONNECTION_PROFILE_[A-Z_]+)", line)
        if profile: bluetooth[profile[1]] = profile[2]
    for group in groups:
        group["parsed_keys"] = len(group["entries"])
        group["declared_count_matches"] = group["parsed_keys"] == group["declared_keys"]
    if not (groups or options or hardware or bluetooth): return None
    return {"location": location, "kind": "runtime_observations_not_a_database_backup",
            "software_options": options, "hardware_flags": hardware,
            "user_parameter_groups": groups, "bluetooth": bluetooth}


def sqlite_info(data):
    if data[:2] == b"\x1f\x8b":
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as f:
            data = f.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ValueError("Database exceeds inspection limit")
    if not data.startswith(b"SQLite format 3\0"):
        return None, None
    c = sqlite3.connect(":memory:")
    try:
        c.deserialize(data)
        c.execute("PRAGMA trusted_schema=OFF")
        integrity = c.execute("PRAGMA integrity_check").fetchall()
        if integrity != [("ok",)]:
            raise sqlite3.DatabaseError("SQLite integrity check failed")
        info = {
            "raw_sha256": hashlib.sha256(data).hexdigest(),
            "raw_bytes": len(data),
            "integrity": integrity,
            "tables": [x[0] for x in c.execute("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")],
        }
        return info, data
    finally:
        c.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("source", type=Path, help="Copied SPY folder on the laptop")
    p.add_argument("--output", type=Path, required=True, help="New host result folder")
    a = p.parse_args()
    if not a.source.is_dir() or a.source.is_symlink():
        p.error("Source must be a regular copied directory")
    a.output.mkdir(parents=True, exist_ok=False)
    report = {"source": str(a.source.resolve()), "physical_car_access": False,
              "files": [], "archives": [], "databases": [], "parameter_snapshots": [], "errors": []}

    def inspect(data, location, name):
        if not name.lower().endswith((".sqlite", ".sqlite.gz", ".db")):
            return
        try:
            info, raw = sqlite_info(data)
            if info:
                index = len(report["databases"])
                output = a.output / f"database-{index:03d}.sqlite"
                output.write_bytes(raw)
                report["databases"].append(dict(info, location=location, name=name,
                                                extracted=str(output)))
        except (ValueError, OSError, sqlite3.DatabaseError) as exc:
            report["errors"].append({"location": location, "error": str(exc)})

    for path in sorted(a.source.rglob("*")):
        if path.is_symlink():
            report["errors"].append({"location": str(path), "error": "Symlink skipped"})
            continue
        if not path.is_file():
            continue
        rel = str(path.relative_to(a.source))
        h = hashlib.sha256()
        with path.open("rb") as f:
            while block := f.read(1024 * 1024): h.update(block)
        report["files"].append({"path": rel, "bytes": path.stat().st_size, "sha256": h.hexdigest()})
        if path.stat().st_size <= LIMIT and path.name.lower().endswith((".sqlite", ".sqlite.gz", ".db")):
            inspect(path.read_bytes(), rel, path.name)
        if path.name.lower().endswith((".tar.gz", ".tgz", ".tar")):
            archive = {"path": rel, "members": []}
            try:
                with tarfile.open(path, "r:*") as t:
                    for index, member in enumerate(t):
                        if index >= 10000:
                            raise ValueError("Archive member limit reached")
                        archive["members"].append({"path": member.name, "bytes": member.size, "regular": member.isfile()})
                        if member.isfile() and member.size <= LIMIT and member.name.lower().endswith((".sqlite", ".sqlite.gz", ".db")):
                            with t.extractfile(member) as f:
                                inspect(f.read(LIMIT + 1), rel + "::" + member.name, member.name.rsplit("/", 1)[-1])
                        elif member.isfile() and member.size <= 8 * 1024 * 1024 and member.name.lower().endswith((".txt", ".bin")):
                            with t.extractfile(member) as f:
                                snapshot = parameter_snapshot(f.read(), rel + "::" + member.name)
                            if snapshot: report["parameter_snapshots"].append(snapshot)
            except (tarfile.TarError, OSError, ValueError) as exc:
                report["errors"].append({"location": rel, "error": str(exc)})
            report["archives"].append(archive)
    names = {x["name"].lower().removesuffix(".gz") for x in report["databases"]}
    report["requested_databases_present"] = {name: name in names for name in sorted(TARGETS)}
    report["all_requested_databases_present"] = TARGETS <= names and not report["errors"]
    report["full_car_database_backup_verified"] = False
    (a.output / "inventory.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"files": len(report["files"]), "archives": len(report["archives"]),
                      "databases": [x["name"] for x in report["databases"]],
                      "parameter_snapshots": len(report["parameter_snapshots"]),
                      "requested_databases_present": report["requested_databases_present"],
                      "errors": report["errors"]}, indent=2))


if __name__ == "__main__":
    main()
