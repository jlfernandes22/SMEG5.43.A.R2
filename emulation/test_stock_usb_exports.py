#!/usr/bin/env python3
"""Exercise original SPYSTORE/SPYTAKE via touch; observe original native calls.

Only local QEMU control sockets are used. No guest calls, injected code, update
packages, device files, physical USB drives, or physical cars are accessed.
"""
import argparse
import json
import time
from pathlib import Path

from run_usb_probe import QMP, RSP

POINTS = {
    0x1273734: "SPYSTORE_CallBackCopy",
    0x1279DB8: "SystemShot_SpyFiles",
    0x1277634: "CommonCollectSpy",
    0x12776C4: "CollectRamdisk_return",
    0x1277850: "CollectArchive_return",
    0x1277880: "CommonCollect_return",
    0x105AE44: "GetUserDataDir",
    0x490808: "open",
    0x2C7DB0: "fopen",
    0x20E3D0: "sysToMonitor",
}


def tap(q, x, y):
    q.call("input-send-event", {"events": [
        {"type": "abs", "data": {"axis": "x", "value": round(x * 32767 / 799)}},
        {"type": "abs", "data": {"axis": "y", "value": round(y * 32767 / 479)}},
        {"type": "btn", "data": {"down": True, "button": "left"}},
    ]})
    time.sleep(.2)
    q.call("input-send-event", {"events": [
        {"type": "btn", "data": {"down": False, "button": "left"}},
    ]})
    time.sleep(.25)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--directory", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--command", choices=["SPYSTORE", "SPYTAKE"], required=True)
    p.add_argument("--prepare", action="store_true", help="Type only; do not confirm")
    p.add_argument("--observe-only", action="store_true", help="Arm native export breakpoints before a separate UI confirmation")
    p.add_argument("--seconds", type=int, default=35)
    a = p.parse_args()
    a.output.parent.mkdir(parents=True, exist_ok=True)
    q = QMP(a.directory / "control.qmp")
    if a.prepare:
        # Config must have focus before the stock RADIO/MEDIA long press.
        q.call("qom-set", {"path": "/machine", "property": "frontpanel-event", "value": 0x1702})
        time.sleep(1)
        q.call("qom-set", {"path": "/machine", "property": "frontpanel-event", "value": 0x1504})
        time.sleep(1)
        for ch in a.command:
            i = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".index(ch)
            tap(q, 40 + (i % 10) * 80, 226 + (i // 10) * 55)
        time.sleep(.5)
        q.call("screendump", {"filename": str(a.output.resolve()), "format": "png"})
        q.close()
        return
    report = {"command": a.command, "physical_car_access": False,
              "guest_code_modified": False, "events": [],
              "scope": ("Native export breakpoints armed before a separate UI trigger" if a.observe_only else
                        "Bounded observation after UI confirmation; earliest calls may precede attachment")}
    # QMP rejects input on a stopped VM. Use the normal touch path first;
    # exported files, not a breakpoint hit alone, determine test success.
    if not a.observe_only:
        tap(q, 57, 416)
    q.call("stop")
    r = RSP(a.directory / "control.gdb")
    r.req("qSupported"); r.req("?"); r.req("Qqemu.PhyMemMode:1")
    installed = []
    stopped = True
    try:
        for pc in POINTS:
            if a.observe_only and POINTS[pc] in ("open", "fopen"):
                continue
            assert r.req(f"Z0,{pc:x},4") == "OK"
            installed.append(pc)
        q.close(); q = None
        deadline = time.monotonic() + a.seconds
        while time.monotonic() < deadline:
            r.send("c"); stopped = False
            try:
                r.recv(); stopped = True
            except TimeoutError:
                r.s.sendall(b"\x03"); r.recv(); stopped = True
                continue
            pc = r.reg(64)
            if pc not in POINTS:
                report["unexpected_stop"] = hex(pc)
                break
            item = {"name": POINTS[pc], "pc": hex(pc), "lr": hex(r.reg(67))}
            if POINTS[pc] in ("open", "fopen"):
                item["path"] = r.string(r.reg(3))
                item["flags_or_mode"] = hex(r.reg(4))
                if POINTS[pc] == "fopen": item["mode"] = r.string(r.reg(4))
            else:
                item["r3"] = hex(r.reg(3))
                item["r4"] = hex(r.reg(4))
                item["r5"] = hex(r.reg(5))
                if POINTS[pc] == "CommonCollectSpy": item["suffix"] = r.string(r.reg(5))
            report["events"].append(item)
            if a.observe_only and POINTS[pc] in ("CommonCollectSpy", "SPYSTORE_CallBackCopy"):
                for address in (0x490808, 0x2C7DB0):
                    if address not in installed:
                        assert r.req(f"Z0,{address:x},4") == "OK"
                        installed.append(address)
            a.output.write_text(json.dumps(report, indent=2) + "\n")
            r.req(f"z0,{pc:x},4"); r.req("s"); r.req(f"Z0,{pc:x},4")
    finally:
        if not stopped:
            r.s.sendall(b"\x03"); r.recv()
        for pc in installed: r.req(f"z0,{pc:x},4")
        r.req("D"); r.s.close()
        if q: q.close()
        q = QMP(a.directory / "control.qmp"); q.call("cont"); q.close()
        report["guest_resumed"] = True
        a.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"command": a.command, "events": len(report["events"]), "trace": str(a.output)}))


if __name__ == "__main__":
    main()
