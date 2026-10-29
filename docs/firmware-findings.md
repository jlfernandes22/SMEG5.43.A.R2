# Phase 2: firmware evidence and extraction

> **Historical phase record.** Statements about unavailable samples, untested extraction, or missing boot evidence describe this phase only. For the current consolidated findings and limits, start with [REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md) and [DEPLOYMENT.md](DEPLOYMENT.md).

No firmware sample was supplied to this workstream. The commands below are ready for a local package; they do not demonstrate a boot or independently verify vendor bytes.

## Evidence

- [pepelxl/psa-smeg-revers README](https://github.com/pepelxl/psa-smeg-revers) explicitly studies 5.43.A.R2 and 6.4.A.R10, identifies SMEG+ as big-endian PowerPC and distinguishes SMEG IV2 ARM. Its “2x400 MHz” claim is not sufficient to choose a dual-core CPU model.
- [KRoperUK architecture](https://smeg.kroper.uk/ARCHITECTURE/) reports VxWorks 6.7 on Freescale MPC5121e/e300. This research targets the same 2015 Peugeot 208 / NAV 5.43.A.R2. Inspect its hardware evidence before assigning a physical unit a board model. No evidence here supports treating SMEG+ as Linux or QNX.
- [Boot chain research](https://smeg.kroper.uk/FLASH_CHAIN/) derives BootROM/U-Boot/updater steps from shipped ELF symbols and messages. It identifies `BSP/SMEG_PLUS_{256,512}/vxWorks.bin`; `flasher.inf` addresses are flash/update locations, not proof of runtime RAM mappings. The full BootROM reset path still needs hardware/package validation.
- [Application decompressor source](https://github.com/KRoperUK/smeg-plus-patches/blob/main/tools/unpack.py) inflates the zlib stream usually at file offset `0x801` in `AppBin/f_BigQuick.bin`. Reported application base is `0x01000000`; symbol addresses translate to file offsets by subtracting that base. This is an application image, not a bootable disk or the complete RTOS.
- [Media container research](https://github.com/KRoperUK/smeg-plus-patches/blob/main/docs/MEDIA_PARTITION.md) identifies `<variant>/system.bin` as gzip-compressed tar for `/SYSTEM/`, including `Application/PKG/abs_symbols_base` and `symbols_bsp`. Runtime settings also reside in distinct user partitions; the update payload is not a NAND dump.
- [pepelxl theme extractor](https://github.com/pepelxl/psa-smeg-revers/blob/main/SMEG_extarct_harm/SMEG_extarct_harm.cpp) extracts themes from `BIG_HARMONY.bin`; it does **not** unpack the whole firmware. It checks `BIGHARMONY`, reads big-endian metadata at `0x820`, addresses payloads in 2048-byte blocks, validates CRC32, skips a four-byte inflated-size field, then zlib-decompresses. Its `_byteswap_ulong` and `system("pause")` make the published C++ Windows-oriented; no Linux build claim is made here.

Research snapshots used locally:

```text
pepelxl/psa-smeg-revers 932db83c6e1518f5b9ddf3050670ab218329ec68
KRoperUK/smeg-plus-patches c5eda38e6b5520015bbbd59bde8caf97c2e4fb7c
```

## Commands

Run from this project root. Supply your own already unpacked, legally obtained update directory. Choose the actual hardware variant (`NAV` below is an example, not an autodetected unit identity). If the download is an outer ZIP/7z/RAR, first list it with the appropriate archive program and unpack into a new empty local directory; do not assume all PSA updates use one outer archive format.

```bash
mkdir -p artifacts
export SMEG_PACKAGE='/absolute/path/SMEG_PLUS_UPG'
python3 scripts/inspect_firmware.py "$SMEG_PACKAGE" > artifacts/firmware-inventory.jsonl
python3 sources/smeg-plus-patches/tools/unpack.py \
  "$SMEG_PACKAGE/NAV/AppBin/f_BigQuick.bin" artifacts/app_nav.bin
python3 sources/smeg-plus-patches/tools/fingerprint.py \
  --image artifacts/app_nav.bin --json > artifacts/app-fingerprint.json
# List the media payload before extracting it:
tar -tzf "$SMEG_PACKAGE/NAV/system.bin" > artifacts/system-members.txt
# Read-only ELF evidence from the actual updater:
readelf -h "$SMEG_PACKAGE/upgrade.out"
python3 sources/smeg-plus-patches/tools/elfsyms.py \
  "$SMEG_PACKAGE/upgrade.out" --class C_UPGRADE
```

Extract `system.bin` with Python's data filter (Python 3.12+; this creates local files only):

```bash
python3 - <<'PY'
import os, tarfile
from pathlib import Path
out = Path('artifacts/system_nav')
out.mkdir(parents=True, exist_ok=False)
with tarfile.open(Path(os.environ['SMEG_PACKAGE']) / 'NAV/system.bin', 'r:gz') as archive:
    archive.extractall(out, filter='data')
PY
```

Keep `BSP/`, `AppBin/`, the media payload, theme payloads and front-panel MCU `RENESAS/FPComSMEG.mot` distinct. Hash the original first, work on copies, and preserve manifests for later verification. The original theme executable can be run on Windows as `SMEG_extarct_harm.exe BIG_HARMONY.bin` in an empty output directory; the exact published source does not justify a blanket `binwalk -e` recipe.

The observed updater checks include per-file control records, module/root CRC cascades, version gates and a media contract. Plainly repacking a tar or editing SQLite does not produce an accepted flash package. This phase intentionally supplies no flashing command.

## Validation performed

Upstream `unpack.py --help` and `fingerprint.py --help` executed successfully with Python 3. Repository sources were inspected; no upstream executable or firmware was executed. The local inspector is standard-library-only and streams file hashes rather than loading entire binaries. Synthetic ELF32 big-endian PowerPC and SQLite fixtures passed the inspector smoke checks. Raw ELF architecture/endian fields are stronger evidence than filenames. Firmware-dependent extraction, CRC validity, variant identification and boot entry points remain untested until a package is supplied.
