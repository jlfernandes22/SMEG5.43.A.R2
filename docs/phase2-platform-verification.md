# Phase 2 platform verification against the supplied package

> **Historical phase record.** Statements about untested execution or hardware describe this phase only. For the current consolidated findings and limits, start with [REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md) and [DEPLOYMENT.md](DEPLOYMENT.md).

Input: `artifacts/phase2/package/SMEG_PLUS_UPG`. This analysis reads original extracted package files without modifying them. Machine-readable evidence, hashes, descriptor bytes and zero-based byte offsets are saved in `artifacts/phase2/platform-evidence.json`.

## Verified architecture and OS

`readelf -h` on `upgrade.out`, independently checked by direct header decoding for five supplied modules, establishes **ELF32, big-endian, PowerPC (EM_PPC = 20), relocatable (ET_REL = 1), entry 0**. The modules are `upgrade.out`, `upgrade_256.out`, `upgrade_lib.out`, `UpgPlugin.out`, and `NAV/DB_DWNL/db_dwnl_gl.out`. They have relocation/linking requirements; `-kernel upgrade.out` is not a valid board boot recipe. Their generic System V ELF ABI label does not identify Linux or QNX.

Both BSP images contain the literal **VxWorks 6.7** twice:

| Image | File size | VxWorks version file offsets | CRC32 |
|---|---:|---|---|
| `BSP/SMEG_PLUS_256/vxWorks.bin` | 6,713,760 | `0x308a40`, `0x528d80` | `731ae273` |
| `BSP/SMEG_PLUS_512/vxWorks.bin` | 6,713,840 | `0x308b80`, `0x528ed0` | `71242c66` |

These are **file offsets**, not guest execution addresses. The kernels start with bytes `94 21 ff e0 7c 08 02 a6` (plausible big-endian PowerPC `stwu r1,-32(r1); mflr r0`), rather than ELF/gzip/U-Boot legacy-image headers. Readable kernel code/data and symbols are already present: there is no evidence from these heads that an outer decompression pass is needed. Generic `file` output claiming OpenPGP is a coincidental magic match, contradicted by the surrounding package, PPC instructions and VxWorks strings. This does not prove that the first file instruction is the board's reset or kernel entry point.

In the **512** kernel:

| File offset | Literal evidence | Interpretation |
|---|---|---|
| `0x51761c` | `Freescale MPC5121E ADS` | BSP targets this SoC family/reference board description |
| `0x517a68` | `e300 Core %s, Boot Vector @ 0x%08X, %s Endian Mode` | e300-aware platform code |
| `0x5434e8` | `VxWorks Edition for ppc603` | Compatible PPC implementation target; not a different physical SoC identification |
| `0x519498` | `usb(0,0)host:vxWorks h=192.168.10.2 e=192.168.10.1 [default fields omitted]` | Embedded example/default boot line; no evidence these endpoints or omitted default fields are active on a vehicle |

The 256 image independently contains MPC5121E ADS and e300 strings as well (exact offsets in JSON). This substantially supports **MPC5121e/e300 + VxWorks 6.7** for the packaged BSP. Bundling both variants does not identify the user's actual board/NAND revision, live CPU frequency, RAM size or active hardware straps. It does not support the earlier two-PowerPC-core claim.

## Verified update-address manifest

Both kernel and `dbsystem.bin` CRCs match the local `flasher.inf` values; these are integrity cross-checks, not authenticity/signature verification.

| BSP variant | Payload | Manifest update address | Manifest/computed CRC32 |
|---|---|---|---|
| 256 | `vxWorks.bin` | `0x420000` | `731ae273` |
| 512 | `vxWorks.bin` | `0x720000` | `71242c66` |
| 256 | `dbsystem.bin` | `0x180000` | `718c41b5` |
| 512 | `dbsystem.bin` | `0x180000` | `215167f7` |

The root `flasher.inf` selects the 512 paths by default; the two variant manifests are present separately. Do not select a unit's board type solely from that root file. Both `dbsystem.bin` descriptors are 40 bytes. The JSON preserves their raw fields without inventing a struct layout.

`upgrade.out` includes NAND-writing messages at file offsets `0x151000` (`WriteNand_Addr`) and `0x151060` (`WriteFileToNAND`), consistent with update destinations in the manifests. These values **must not be copied into a QEMU runtime memory map as RAM/kernel load addresses**.

## Bootloader evidence and limits

The updater explicitly supports BootRom and U-Boot stages:

- `upgrade.out:0x14ae44`: `BootRom version :`
- `upgrade.out:0x14ae58`: `UBoot version :`
- `upgrade.out:0x151300`: diagnostic asserting the CRC of `u-boot-nand.bin` is OK
- `upgrade.out:0x1514d0` / `0x151514`: product/media U-Boot version messages, with `%02d.%02d` placeholders
- Kernel symbols include `UBootVersionShow`, `getUBootVersion`, `BootRomStart` and `usrInit`.

A recursive package filename check finds **no separate U-Boot/BootROM-named payload**, and neither BSP image contains a literal `U-Boot` banner. The updater's generic ability to update U-Boot does not supply the current unit's U-Boot executable or version. The `BootRom` name is also used for software functions in the VxWorks image; it should not automatically be equated to a complete dump of immutable SoC ROM. Kernel images may participate in that named stage, as the updater messages suggest.

Therefore the defensible chain is: packaged VxWorks BSP/kernel plus application/data payloads; updater logic recognizes BootRom, U-Boot and front-panel MCU stages. **Exact reset vector, U-Boot version/image, initial register state, hardware revision and complete execution order remain unverified** until a ROM/flash dump, serial boot trace or symbol/call analysis resolves them.

## Reproduction

```bash
readelf -h artifacts/phase2/package/SMEG_PLUS_UPG/upgrade.out
python3 scripts/inspect_firmware.py \
  artifacts/phase2/package/SMEG_PLUS_UPG/BSP
```

No flashing, hardware diagnostics, downloaded executables or firmware execution was performed in this workstream. The unit's actual installed hardware and runtime behaviour are still independent of the bundle contents.
