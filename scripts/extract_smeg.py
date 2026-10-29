#!/usr/bin/env python3
"""Extract traceable SMEG evidence, never invent CAN identifiers or payloads.

Default acquisition: git clone --depth 1 https://github.com/morluto/rea.
YAML requires optional PyYAML; without it YAML matches remain text evidence and
the report explicitly records that structured parsing was unavailable.
"""
import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess
from pathlib import Path

SMEG = re.compile(r"(?<![A-Za-z0-9_])smeg(?:\+|iv2|[ _-]?plus)?(?![A-Za-z0-9_])", re.I)
try:
    import yaml
except ImportError:
    yaml = None


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def walk(value, path="$", inherited=False):
    """Smallest explicitly SMEG-labelled object, not the entire containing file."""
    if isinstance(value, dict):
        direct = any(SMEG.search(str(k)) or
                     (isinstance(v, (str, int, float)) and SMEG.search(str(v)))
                     for k, v in value.items())
        if direct:
            # Keep labelled record; large bodies stay in source, not the report.
            yield {"pointer": path, "record": value} if len(json.dumps(value)) < 16000 else {
                "pointer": path, "record": {str(k): v for k, v in value.items()
                    if not isinstance(v, (dict, list))}, "nested_record_omitted": True}
        for k, v in value.items():
            yield from walk(v, path + "/" + str(k).replace("~", "~0").replace("/", "~1"))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from walk(v, path + "/" + str(i))


def scan(repo):
    report = {"repository": git(repo, "remote", "get-url", "origin"),
              "commit": git(repo, "rev-parse", "HEAD"),
              "collected_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
              "yaml_parser": "PyYAML safe_load_all" if yaml else "unavailable; text evidence only",
              "counts": {"tracked_files": 0, "structured_files": 0, "text_files": 0},
              "structured_entries": [], "text_evidence": [], "skipped": [],
              "can_frames": [], "diagnostic_protocols": [],
              "limitations": ["Text matches are candidate evidence, not automatically verified CAN frames.",
                  "Repository claims require validation against this unit and captured traffic."]}
    files = subprocess.check_output(["git", "-C", str(repo), "ls-files", "-z"]).decode().split("\0")
    for relative in filter(None, files):
        report["counts"]["tracked_files"] += 1
        p = repo / relative
        if not p.is_file() or p.stat().st_size > 4_000_000:
            report["skipped"].append({"file": relative, "reason": "not regular or exceeds 4 MB"})
            continue
        data = p.read_bytes()
        if b"\0" in data[:8192]:
            continue
        try:
            content = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        report["counts"]["text_files"] += 1
        matches = [{"line": i, "text": line[:600]} for i, line in enumerate(content.splitlines(), 1)
                   if SMEG.search(line)]
        if matches:
            report["text_evidence"].append({"file": relative,
                "sha256": hashlib.sha256(data).hexdigest(), "matches": matches})
        suffix = p.suffix.lower()
        if suffix not in (".json", ".yaml", ".yml"):
            continue
        report["counts"]["structured_files"] += 1
        if not matches:
            continue
        try:
            documents = [json.loads(content)] if suffix == ".json" else list(yaml.safe_load_all(content)) if yaml else []
            for doc in documents:
                for record in walk(doc):
                    report["structured_entries"].append({"file": relative, **record,
                        "matching_source_lines": [m["line"] for m in matches]})
        except Exception as exc:
            report["skipped"].append({"file": relative, "reason": "parse failure: " + str(exc)[:200]})
    return report


def supplement(repo):
    """Parse pepelxl's Markdown as a separately attributed supplementary source."""
    result = {"repository": git(repo, "remote", "get-url", "origin"),
              "commit": git(repo, "rev-parse", "HEAD"), "telemat_ids": [],
              "frame_examples": [], "diagnostic_evidence": [],
              "limitations": ["Examples are source transcriptions, not bench-tested transmit instructions.",
                  "No diagnostic request/response pair or service payload is established here.",
                  "The documented local display CAN bitrate is unspecified."]}
    info = repo / "can_info.md"
    content = info.read_text()
    lines = content.splitlines()
    block = re.search(r"TELEMAT\(smeg\)\s*=([^\n]*(?:\n(?!\s*COMBINE).*)*)", content)
    # Stop at blank separation, preserving the ECU attribution boundary.
    if block:
        body = block.group(1).split("COMBINE(")[0]
        # Link anchors can contain a different/incorrect ID; extract visible labels only.
        body = re.sub(r"\[([^]]+)\]\([^)]*\)", r"\1", body)
        result["telemat_ids"] = list(dict.fromkeys(s.upper().replace("0X", "0x")
            for s in re.findall(r"0x[0-9A-Fa-f]{3}", body)))
    ids = {s.lower() for s in result["telemat_ids"]}
    for filename in ("can_info.md", "can_smeg_local.md"):
        text = (repo / filename).read_text()
        sections = list(re.finditer(r"^### ID (0x[0-9A-Fa-f]+).*?$", text, re.M))
        for i, match in enumerate(sections):
            end = sections[i + 1].start() if i + 1 < len(sections) else len(text)
            # Generic frame headings must not spill into the preceding ID.
            body = re.split(r"\n### ", text[match.end():end], maxsplit=1)[0]
            ident = match.group(1)
            if filename == "can_info.md" and ident.lower() not in ids:
                continue
            # These documents also contain application payloads with ISO-TP removed.
            # Even short such strings are not raw CAN frames.
            if "без транспортного уровня" in body:
                continue
            examples = re.finditer(r"Пример:\s*`?([0-9A-Fa-f ]{2,})([^\n]*)", body)
            for example in examples:
                if re.search(r"rcc|nac", example.group(2), re.I):
                    continue
                raw = example.group(1)
                payload = raw.strip().replace(" ", "")
                if not payload or len(payload) % 2 or len(payload) > 16:
                    continue  # CAN ISO-TP multi-frame application strings aren't raw frames.
                result["frame_examples"].append({"file": filename,
                    "line": text.count("\n", 0, match.start()) + 1,
                    "can_id": ident, "payload_hex": payload, "dlc": len(payload) // 2,
                    "example_line": text.count("\n", 0, match.end() + example.start()) + 1,
                    "example_text": example.group(0).strip(),
                    "bus": "CAN INFO DIV 125 kbit/s fault tolerant" if filename == "can_info.md" else "local display CAN (bitrate unknown)",
                    "source_description": body.strip().splitlines()[0]})
    for i, line in enumerate(lines, 1):
        if re.search(r"0x(?:524|5E4|664)|^### (?:Init|Keep-alive|DIAG)|ISO 15765-2", line):
            result["diagnostic_evidence"].append({"file": "can_info.md", "line": i, "text": line.strip()})
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", type=Path, default=Path("sources/rea"))
    ap.add_argument("--url", default="https://github.com/morluto/rea")
    ap.add_argument("--clone", action="store_true", help="clone only if the repo path is absent")
    ap.add_argument("--supplemental", type=Path)
    ap.add_argument("--out", type=Path, default=Path("artifacts/phase1"))
    args = ap.parse_args()
    if not args.repo.exists() and args.clone:
        args.repo.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "--depth", "1", args.url, str(args.repo)], check=True)
    report = scan(args.repo)
    if args.supplemental:
        report["supplemental"] = supplement(args.supplemental)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "smeg_intelligence.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    summary = ["# Phase 1 SMEG intelligence", "", f"Primary source: {report['repository']}",
               f"Commit: `{report['commit']}`", "",
               f"Scanned {report['counts']['tracked_files']} tracked files; "
               f"{report['counts']['structured_files']} JSON/YAML files; "
               f"{len(report['structured_entries'])} explicitly SMEG-labelled structured records; "
               f"{len(report['text_evidence'])} matching text files.", "",
               "The primary repository currently describes REA: Reverse Engineer Anything, a generic reverse-engineering toolkit. "
               "It does not establish any SMEG CAN frame or ECU configuration in this scan.", ""]
    if "supplemental" in report:
        s = report["supplemental"]
        summary += [f"Supplemental source: {s['repository']} at `{s['commit']}`.", "",
            "TELEMAT(smeg) IDs transcribed from can_info.md:4–28 (125 kbit/s fault-tolerant CAN INFO DIV): " + ", ".join(s["telemat_ids"]), "",
            "Source labels 0x524 keep-alive, 0x5E4 init, 0x664 DIAG. Generic diagnostic description states ISO 15765-2. "
            "Keep-alive: 8 bytes / 1000 ms, contents unknown; init: 8 bytes once after wake. "
            "No exact diagnostic service payload, paired tester RX/TX IDs, or proven UDS/KWP service layer is provided.", "",
            "| Bus | ID | Example payload | DLC | Source |", "|---|---|---|---|---|"]
        summary += [f"| {r['bus']} | {r['can_id']} | `{r['payload_hex']}` | {r['dlc']} | {r['file']}:{r['example_line']} |" for r in s["frame_examples"]]
        summary += ["", "These are documented examples, not a boot recipe or verified hardware transmit commands. "
                    "The JSON retains exact source descriptions, line evidence, and protocol limitations."]
    (args.out / "SUMMARY.md").write_text("\n".join(summary) + "\n")
    print(json.dumps({"out": str(args.out), "counts": report["counts"],
        "structured_entries": len(report["structured_entries"]), "matching_text_files": len(report["text_evidence"])}))


if __name__ == "__main__":
    main()
