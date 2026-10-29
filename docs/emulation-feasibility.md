# SMEG+ 5.43.A.R2 emulation feasibility

> **Historical planning document.** Statements that no sample or successful boot was available, and tasks described as future work, reflect this early phase. For the current consolidated findings and limits, start with [REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md) and [DEPLOYMENT.md](DEPLOYMENT.md).

Research date: 2026-10-25. These are source-backed starting points, not a successful boot of the local firmware.

## Architecture and boot evidence

[bousqi's on-unit console capture and firmware analysis](https://github.com/bousqi/SMEG_PLUS#smeg-hardware) identify **VxWorks 6.7**, WIND 2.12, for **Freescale MPC5121E ADS**, and describe U-Boot preceding VxWorks. The image is `vxWorks.bin`; the updater references `u-boot-nand.bin`. This is evidence against assuming QNX or Linux from the processor alone. [NXP's processor documentation](https://www.nxp.com/products/MPC5121e) identifies a 32-bit e300 core, integrated graphics, serial controllers and audio acceleration. [The exact-build research project](https://github.com/KRoperUK/smeg-plus-patches) targets 5.43.A.R2 on a 2015 Peugeot 208; its [function emulator](https://smeg.kroper.uk/EMULATION/) uses 32-bit big-endian PowerPC.

Reported load addresses, **not NAND offsets or a complete physical memory map**, from [bousqi](https://github.com/bousqi/SMEG_PLUS#smeg-memory-mapping):

| Address | Reported purpose | Local status |
| --- | --- | --- |
| `0x00010000` | ELF loading space | Verify against local images |
| `0x00200000` | VxWorks image | Verify reset/entry and symbol pointers |
| `0x01000000` | Inflated BigQuick application | Verify container and extracted length |

The same source reports TrueFFS volumes including `/SYSTEM`, `/USER_DATA`, `/bd0` (USB), and `/sdhc:0` (internal storage). None of this establishes NAND page/OOB geometry, controller MMIO bases, interrupt routing, reset mappings or CPU register state. Those must be recovered before a board implementation can boot.

## QEMU scope

[QEMU's PowerPC documentation](https://www.qemu.org/docs/master/system/target-ppc.html) directs users to the installed machine list. Its [documented embedded machines](https://www.qemu.org/docs/master/system/ppc/embedded.html) do not list MPC5121E/SMEG+. A generic `ppce500` machine is a different board/core family; attaching a firmware file to it does not reproduce this board.

Read-only environment checks:

```sh
qemu-system-ppc --version
qemu-system-ppc -machine help
qemu-system-ppc -cpu help
```

A boot command and compilable board C implementation are deliberately deferred until the BSP requirements are established. A guessed UART address, RAM size or reset PC would create misleading executable-looking output.

Recommended implementation gates:

1. Hash the supplied package; inspect ELF `e_machine`, endianness, entry points, relocations and loadable segments. Find kernel version and BSP strings locally. Select the applicable 256/512 MB image from actual package evidence.
2. Recover reset vector, U-Boot environment, RAM controller setup, IMMR mapping, timer/timebase, IPIC interrupt controller and PSC console from the BSP and NXP reference manual.
3. Implement a QEMU machine with verified e300-compatible CPU behavior, RAM, reset mappings and diagnostic MMIO logging. Implement actual register semantics for peripherals reached before the console. Fail visibly on unknown accesses rather than silently treating every register as zero.
4. Reach kernel console with explicit acceptance criteria: serial output, increasing tick counter, working interrupts and repeatable boot. Add NAND/FlashFX/TrueFFS only after geometry and translation are understood.
5. Implement storage, secondary MCU communication, CAN, graphics and audio incrementally. These are separate milestones; a console boot does not establish a working UI.

### Storage attachment

`system.bin` is an update payload, not necessarily a bootable block device. Keep these distinct: raw NAND dump with OOB/ECC; logical filesystem image; compressed update archive; microSD disk image. Each needs a different device/model. A QEMU NAND model needs the recovered NAND geometry and controller; `-drive if=ide` invents hardware the BSP may never probe. For a verified whole-card image, attach a raw, read-only backend to the **implemented SDHC controller**, using its actual QEMU device binding. A filename alone is insufficient to specify that binding.

## Useful intermediate emulation

[The exact-build project documents](https://smeg.kroper.uk/EMULATION/) a Unicorn function harness (`tools/ppcemu.py`) and BigQuick unpacker. It runs individual application functions with explicit call stubs; it does **not** boot VxWorks or provide display/DBUS. This is a practical intermediate validation target. Reproduce a small function with known input/output before undertaking complete board emulation. Record every stub return and unmapped access as an assumption, not a hardware observation. Its published command examples require that project's tools and a user-supplied image; they have not been executed here.

## Database and feature constraints

[The database research](https://smeg.kroper.uk/DATABASES/) distinguishes seed databases in `Data_base/sqlite/` inside `system.bin` from live databases in `/USER_DATA/user_data/sqlite/`. It explicitly does not establish the schema of `config_options.sqlite`; some live stores are gzip-compressed and have CRC sidecars. Consequently no credible Stop/Start, Apps or navigation `UPDATE` statement can be supplied before inspecting the actual schema and tracing its consumer. Editing a seed also need not change existing live settings.

Start with read-only inspection of a working copy:

```sh
file extracted/config_options.sqlite
sqlite3 -readonly extracted/config_options.sqlite 'PRAGMA integrity_check;'
sqlite3 -readonly extracted/config_options.sqlite '.schema'
sqlite3 -readonly extracted/config_options.sqlite \
  "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
```

If `file` reports gzip, decompress to a separate analysis copy first. Identify exact keys, types, bounds and ownership from disassembly; back up live data before any eventual offline edit. A future patch should use a transaction, assert the original value and affected-row count, and validate integrity after committing. This document supplies no invented feature schema.

Native CarPlay/Android Auto is not established as a configurable capability of this build. [The capability analysis](https://smeg.kroper.uk/CAPABILITIES/) reports no CarPlay stack in the inspected application. Do not treat missing strings as a proof that a port is impossible, or an existing iPod authentication chip as proof of CarPlay support. A new protocol/video/UI implementation and verified hardware capabilities would be required. Aftermarket projection hardware is a separate integration approach, not a SQLite unlock. Navigation availability likewise requires matching application variant, hardware, map format and legitimate activation; a menu flag alone does not supply them. Stop/Start engine behavior belongs to the vehicle ECUs; any discovered head-unit flag must be distinguished from actual engine control.
