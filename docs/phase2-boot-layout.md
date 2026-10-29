# Phase 2: local boot and storage evidence

> **Historical phase record.** Statements about unresolved load addresses, missing boot evidence, or future emulation work describe this phase only. For the current consolidated findings and limits, start with [REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md) and [DEPLOYMENT.md](DEPLOYMENT.md).

Analyzed package: `artifacts/phase2/package/SMEG_PLUS_UPG`. No source package files were modified. Bounded evidence, hashes, exact string offsets and archive inventories are in `artifacts/phase2/boot-layout-evidence.json`. All offsets below are **file offsets** unless explicitly labeled otherwise.

## Locally confirmed kernel identity

The 512 variant `BSP/SMEG_PLUS_512/vxWorks.bin` contains:

| File offset | String |
| --- | --- |
| `0x308b80` | `VxWorks 6.7` |
| `0x3806a8` | `WIND version 2.12` |
| `0x51761c` | `Freescale MPC5121E ADS` |
| `0x519498` | USB-host VxWorks boot line |

The boot line includes fixed host/device IP values, but its presence does not prove that an actual unit currently boots from USB. Likewise a BSP banner identifies the compiled target; PCB markings and hardware measurements remain stronger evidence of the installed board. Earlier literature's generic VxWorks 5.5 references are not the version identified by these local images.

## Flash manifests and the 40-byte dbsystem records

| Variant | Kernel bytes | Manifest kernel flash address | Kernel CRC32 | dbsystem manifest address |
| --- | ---: | --- | --- | --- |
| `SMEG_PLUS_256` | 6,713,760 (`0x6671a0`) | `0x420000` | `731ae273` | `0x180000` |
| `SMEG_PLUS_512` | 6,713,840 (`0x6671f0`) | `0x720000` | `71242c66` | `0x180000` |

These values come directly from the respective `flasher.inf` and kernel files. The term flash address follows the flasher manifest convention; these are not the kernel's RAM load address. NAND page/OOB addressing and bad-block behavior still need driver analysis.

Each `dbsystem.bin` is exactly **40 bytes**, not gzip and not a filesystem image. Interpreted as ten big-endian 32-bit words:

- Word 0 equals its variant's kernel flash address in `flasher.inf`.
- Word 1 equals the exact kernel byte length.
- Word 2 equals both the manifest checksum and independently calculated `zlib.crc32(vxWorks.bin)`.
- Words 3 through 8 are zero in both supplied variants; their semantics are unestablished.
- Word 9 equals `zlib.crc32(dbsystem.bin[:36])`: `03668326` (256), `46f5d213` (512).

This establishes record relationships and CRC coverage in this package, without recovering every field's purpose. It prevents attempting to mount or decompress dbsystem.

## Loader components and missing reset-stage image

The actual `upgrade.out` contains `u-boot-nand.bin` at `0x1512ac`, U-Boot update/version/error diagnostics nearby, Renesas update diagnostics at `0x14f664` onward, and a boot-ROM NAND-write diagnostic at `0x151060`. A recursive filename inventory finds **no file named for U-Boot or NAND** in this package. References to an optional update operation do not supply the actual installed loader, its environment, reset mapping or version.

`NAV/system_data.bin` is gzip-compressed tar with only `ssm_boot.out` (212,469 bytes) and its sidecar. Its ELF header identifies a 32-bit, big-endian, PowerPC relocatable object (`EI_CLASS=1`, `EI_DATA=2`, `e_type=1`, `e_machine=20`). Within that member, bounded strings identify loading boot/base/postponed modules and BigQuick. These establish a boot-module loader component, not a self-contained reset-stage executable. They do not establish the call order or entry register state.

## Archive contents versus installed filesystems

The supplied module payloads are update archives:

| Payload | gzip-tar members | Sum of member bytes |
| --- | ---: | ---: |
| `NAV/system.bin` | 845 | 32,913,331 |
| `AUDIO_BT/system.bin` | 844 | 32,710,671 |
| `AUDIO_BT_256/system.bin` | 235 | 12,736,191 |
| `NAV/system_data.bin` | 2 | 212,572 |

The `system.bin` archives contain top-level `AVR_img`, `Application`, `Data_base`, `internet_default`, `ring_tones`, and `wait_tones`. These are tar member directories, not disk partition boundaries. Compressed archive size, summed file sizes and physical NAND allocation are different quantities.

Local kernel and updater strings corroborate these runtime names:

| Name | Local evidence | Interpretation limit |
| --- | --- | --- |
| `/SYSTEM` | Kernel `0x51ab40`; updater directory/file paths | Expected installed media tree; read-only status requires runtime/driver evidence |
| `/SYSTEM_DATA` | Kernel `0x5196f4`; updater `/SYSTEM_DATA/ssm_boot.out` | Boot/support data paths |
| `/SYSTEM_TMP_DATA` | Kernel `0x51ab54`; updater update-state paths | Expected temporary update state |
| `/USER_DATA` | Kernel `0x51ab74`; updater `/USER_DATA/user_data/sqlite/` | Live database path referenced by updater |
| `/USER_DATA_BACKUP` | Kernel `0x51ab8c`; corresponding SQLite backup path | Distinct backup namespace |
| `/EXTENDED_PARTITION` | Kernel `0x51abac` | Name exists; allocation/content unestablished |
| `/sdhc:0`, `/sdhc:1` | Kernel `0x51549c`, `0x516348`; updater cartography/user-guide format diagnostics | SDHC logical volume roles; capacity/layout need analysis |
| `/romfs` | Kernel `0x519914` and AXE scheduler paths | ROMFS namespace present |
| `/bd0` | Kernel search-path list and updater `/bd0/SMEG_PLUS_UPG` | Update-media namespace |

The kernel includes FlashFX strings and NAND tools. Generic tool help mentions both 512-byte and 2-KiB NAND pages; **this is not proof of this unit's page geometry**. Similarly, strings naming Linux and QNX partition types belong to a generic partition-type table and do not identify the running OS or installed partition types.

## Emulation implications

Keep three address domains separate: flash update destinations (`0x420000`/`0x720000`), reported runtime RAM loads (kernel `0x00200000`, application `0x01000000`, from earlier cited research), and the file offsets recorded here. No local instruction-level analysis in this phase independently establishes the runtime load bases.

The update package cannot currently be passed to a generic QEMU virtual drive to obtain a boot. Remaining inputs are the installed loader/reset state, RAM and MMIO map, NAND geometry/ECC/bad-block and FlashFX translation, interrupts/timers, console, secondary MCU handshake and graphics. Next work should trace the kernel initialization and `ssm_boot.out` relocations against the validated local images, then capture a bench serial boot log. Preserve both BSP variants until the physical target is identified.
