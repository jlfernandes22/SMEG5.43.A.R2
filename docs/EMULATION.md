# Experimental SMEG+ emulation

This repository contains a custom QEMU machine for investigating SMEG+ 5.43.A.R2 firmware on a Linux host. It is a partial MPC5121E model with a host graphics bridge. It is not a complete model of an OEM head unit, a vehicle simulator, or evidence that a change is safe to install on hardware.

Firmware, extracted applications, populated NAND images, and vehicle backups are not supplied. You must provide a firmware package you are entitled to use. Keep firmware-derived images, logs, screenshots, and extraction manifests local; they can contain proprietary material or personal information.

## What executes

The [board implementation](../emulation/mpc5121e_smeg.c) creates one big-endian PowerPC `e300c4` CPU. It loads a raw BSP `vxWorks.bin` at `0x00200000` and starts at `_sysInit`, `0x00200038`. This direct-kernel fixture supplies initial state that physical boot ROM and U-Boot would normally establish; those boot stages do not execute.

| Component | Implemented scope and limits |
| --- | --- |
| CPU and interrupts | QEMU PowerPC translation, timebase/decrementer, and partial IPIC, PSC and eDMA behavior. Clock and reset state include explicit assumptions. |
| NAND | [NFC model](../emulation/smeg_nfc.h) with register-driven reads, programming, erases and interrupts. Synthetic media uses 2,048 data bytes plus 64 spare bytes per page, 64 pages per block, no initial bad blocks and ideal error-free ECC. It does not reproduce physical NAND wear or error behavior. |
| Front panel and touch | A [virtual secondary MCU peer](../emulation/smeg_mcu_peer.h) handles the recovered transport, keys and touch samples. Optional bench status fixtures are simulated inputs. They are not measurements of a vehicle or physical CAN traffic. |
| Display | [DIU scanout](../emulation/smeg_diu.h) presents guest RAM through an 800 × 480 QEMU display surface. The native MBX draw engine remains incomplete. |
| Graphics | The [GLES bridge](../emulation/smeg_soft_gles.c) intercepts selected exact-build application API entry points and dispatches them to host EGL/compatibility OpenGL, using `libffi` and a PVRTC decoder. It adapts the PowerPC ABI and guest memory; it does not emulate the MBX GPU. Unsupported calls remain on the native instruction path and can fail. |
| Removable storage | Optional virtual USB mass storage through patched big-endian EHCI and an optional [SDHC model](../emulation/smeg_sdhc.h). These use image files. |
| Bluetooth and other peripherals | An HCI UART transport exists, but a UART model alone does not establish a working Bluetooth stack or radio. Audio, navigation peripherals, physical ECU behavior and complete board timing are not established. |

The launchers use `-accel tcg,thread=single -smp 1`. An x86 host must translate the PowerPC instructions; KVM cannot accelerate this cross-ISA guest. QEMU 9.2's `ppc-softmmu` target does not enable MTTCG. Extra host cores can help Mesa workers and the build, but do not make this guest CPU execute in parallel. UI responsiveness and host benchmarks are not predictions of hardware performance.

## Host requirements and QEMU source

The supported starting point is Linux with GNU command-line tools and Mesa EGL/OpenGL. A graphical desktop is needed for the GTK window; the renderer tests can run through surfaceless Mesa. Windows, macOS and other host architectures have not been validated by this release.

Install these through your host's package manager:

- A C/C++ toolchain, Git, Bash, Python 3.12 or newer, Ninja, Meson 1.5 or newer, and `pkg-config`.
- Development headers and libraries for GLib, Pixman, zlib, GTK 3, EGL, desktop OpenGL and `libffi`; Mesa's software renderer must also be available at runtime.
- `mtools` (`mcopy` and `mdir`) for populating the native-formatted virtual filesystem.
- For native USB module/package builds: Clang with the PowerPC backend and `dosfstools` (`mkfs.vfat`). These are additional to the host QEMU toolchain.

The build, extraction, NAND preparation, launch and QMP control commands below use Python's standard library. Optional disassembly/evidence scripts need `capstone`; ELF alias regeneration needs `pyelftools`; screenshot-based integration checks need `Pillow`. Those optional packages are not needed for the basic build and firmware-free checks.

Run commands from the repository root. Obtain the pinned upstream QEMU source in a new directory:

```sh
mkdir -p sources
git clone --depth 1 --branch v9.2.0 https://gitlab.com/qemu-project/qemu.git sources/qemu
git -C sources/qemu rev-parse HEAD
```

The expected commit is `ae35f033b874c627d81d51070187fbf55f0bf1a7`. Other QEMU versions require porting and review; the patch scripts deliberately reject changed source anchors. QEMU configuration may fetch its pinned build dependencies if they are not already available.

```sh
SMEG_BUILD_JOBS=4 bash emulation/build.sh
build/qemu/qemu-system-ppc --version
build/qemu/qemu-system-ppc -machine help
```

The machine list must contain `smeg-mpc5121e`. [build.sh](../emulation/build.sh) installs the board and graphics code into that QEMU checkout, adds the [CPU API hook](../emulation/patch_qemu_gles.py), patches [EHCI byte ordering and port speed reporting](../emulation/patch_qemu_ehci.py), and applies an experimental [MPC5121E-specific `rfi` correction](../emulation/patch_qemu_rfi.py). The source tree will therefore be modified and the version may report `dirty`. The build enables GTK and disables QEMU's own OpenGL display frontend; the bridge separately links EGL and OpenGL.

The bundled PowerVR decompressor has its own [MIT license](../emulation/powervr/LICENSE.txt) and [pinned source hashes](../emulation/powervr/provenance.json). [reference_nfc.c](../emulation/reference_nfc.c) is reference material with [separate provenance](../emulation/reference_nfc.provenance.json) and is not compiled into the emulator. Retain upstream license notices when redistributing source or binaries. This repository's license does not grant rights to OEM firmware.

## Firmware-free validation

These checks exercise production graphics/display code and the installed EHCI patch without executing firmware or opening hardware:

```sh
python3 emulation/test_gles_metadata.py
python3 emulation/test_diu_scanout.py
python3 emulation/test_ehci_fsl_speed.py
bash emulation/test_soft_gles.sh
```

For the public documentation audit on 2026-10-29, all four passed on x86_64 CachyOS with Python 3.14.7, GCC 16.2.1, Ninja 1.13.2 and Mesa 26.2.4/llvmpipe. The checks cover graphics ABI metadata, DIU fast/reference equality across 1,522 frames, EHCI speed reporting, and actual Mesa pixel/texture/PVRTC behavior. They validate those boundaries; they do not establish a complete firmware boot, working application menus or hardware equivalence.

Known failing check: `python3 emulation/test_gpio_board.py` currently fails its 256 MiB strap assertion `(read_gpio(&s,0x700)&0x700)==0`. The implementation selects strap index 4 for the virtual 256 MiB PLUS profile, while this test expects index 0. This discrepancy remains unresolved; do not treat the 256 MiB path as release-validated.

## Prepare a fresh synthetic 512 MiB NAND

The following path uses only your update package and newly generated image files. It does not require a physical-unit dump or an existing private artifact. It targets the `SMEG_PLUS_512` BSP and `NAV` application. The current [population script](../emulation/populate_flash.py) fixes that layout; changing RAM or renaming an image does not turn it into a 256 MiB configuration.

Replace `firmware.zip` with your local archive. The extraction destination must be new. The archive must contain `SMEG_PLUS_UPG/` with the BSP and NAV payloads used below.

```sh
python3 scripts/extract_package.py firmware.zip artifacts/phase2/package
python3 scripts/extract_payloads.py artifacts/phase2/package/SMEG_PLUS_UPG artifacts/phase2
python3 emulation/make_flash.py --variant 512 --size-mib 512 \
  --application NAV --output artifacts/phase3/nand-format.raw
```

[make_flash.py](../emulation/make_flash.py) writes an erased synthetic NAND and seeds selected original update payloads in reserved areas. It does not fabricate FlashFX allocation records. Its 512 MiB data image occupies 553,648,128 bytes including spare bytes. The launcher accepts complete 256 or 512 MiB data images with this page layout; a ZIP, `system.bin`, decompressed `app.bin`, or plain logical filesystem is not an interchangeable NAND backend.

Let the original kernel initialize the virtual storage:

```sh
SMEG_NAND=artifacts/phase3/nand-format.raw \
  bash emulation/launch.sh
```

The console and QEMU monitor share the terminal. Allow the native BBM/VBF/DOSFS formatting to finish. At the VxWorks shell, use `devs` and, for example, `dosFsShow "/SYSTEM_DATA", 2` to inspect mounts. A shell prompt alone is not proof that every volume is ready. Switch to the QEMU monitor with Ctrl+A, C and enter `quit` once storage initialization has completed. Do not populate an image while QEMU has it open.

Create the populated copy in new output/work paths:

```sh
python3 emulation/populate_flash.py \
  --input artifacts/phase3/nand-format.raw \
  --output artifacts/phase3/nand-complete.raw \
  --work artifacts/phase3/populate
```

This preserves the discovered native FlashFX structure, copies update files into its volumes, and initializes user databases from the package's default seeds. It also creates documented startup/skin state. Those defaults are generated emulator state, not recovered vehicle settings. The scripts refuse conflicting output paths; use new names for a new experiment.

This preparation sequence is implemented by the supplied scripts, but a clean-room archive-to-UI run is not covered by the firmware-free checks above. Native formatting, population and a subsequent cold boot are required validation steps for each supplied package. An image that reformats unexpectedly, cannot mount its populated volumes or repeatedly restarts has not passed.

## Launch and inspect the application

```sh
bash emulation/launch_ui.sh
```

On first use this copies `nand-complete.raw` to the mutable `nand-interactive.raw`; later launches reuse that session image. To use a different prepared copy, set `SMEG_NAND` explicitly. Supplying it skips the default copy. NAND writes persist, so keep a separate pristine template and close QEMU before copying an image.

The default UI uses Mesa software rendering, GTK and the graphics bridge. It also enables selected host implementations of native application RAM copy/fill exports. Use `SMEG_FAST_MEM=0` for comparisons that retain those guest instructions. Host thread pinning is off by default; `SMEG_PIN_THREADS=1` is an optional Linux experiment requiring CPU selections appropriate to the host topology.

```sh
python3 emulation/ui_control.py --socket artifacts/phase3/interactive.qmp --status
python3 emulation/ui_control.py --socket artifacts/phase3/interactive.qmp \
  --screenshot artifacts/phase3/interactive.ppm
python3 emulation/ui_control.py --socket artifacts/phase3/interactive.qmp --quit
```

[ui_control.py](../emulation/ui_control.py) talks to this local QEMU instance. Touch and panel actions exercise virtual input paths. The feature/demo launchers additionally select simulated vehicle state and prepared media; they are separate experiments with extra local prerequisites.

| Variable | Meaning |
| --- | --- |
| `SMEG_KERNEL` | Raw user-supplied kernel; defaults to the extracted `SMEG_PLUS_512/vxWorks.bin`. |
| `SMEG_NAND` | Writable complete NAND image; default headless input is `artifacts/phase3/nand-complete.raw`. |
| `SMEG_RAM_SIZE` | Guest RAM, default `512M`. Keep it consistent with the BSP and NAND profile. |
| `SMEG_FLASH` | Optional legacy read-only linear flash backend. Unset for the synthetic NAND workflow; no separate `flash.raw` is required. |
| `SMEG_SOFT_GLES` | `1` enables the host API bridge. `0` exercises the incomplete native graphics path and is not expected to provide an equivalent UI. |
| `SMEG_GL_RENDERER` | `software` selects Mesa software rendering; `auto` leaves vendor selection available for a host-specific comparison. |
| `LP_NUM_THREADS` | Mesa worker limit; the generic launcher defaults to 8. This does not add guest vCPUs. |
| `SMEG_USB_MEDIA` / `SMEG_SD_MEDIA` | Optional virtual media templates. The launcher creates writable working copies; use distinct session paths when sharing a template. |

Useful validation includes native serial boot output, mounted volumes that survive a process restart without reformatting, native application rendering, and input causing the expected application transition. Preserve the exact repository revision, upstream QEMU commit, firmware hashes, environment variables and host renderer with a local result. Review logs and images for private content before sharing them. A screenshot or one successful API test does not establish peripheral completeness, update safety, physical timing or compatibility with an installed head unit.

Live HCI diagnostics and host-bond reuse require an explicit phone `--peer`; no phone address is selected by default. The live launcher forwards `SMEG_HCI_PEER_ADDRESS` when set. This is separate from the car-probe `SMEG_BLUETOOTH_ADDRESS` setting. The UI pairing driver also requires the expected `--name`. Offline HCI tests use synthetic peers and do not open a Bluetooth controller.
