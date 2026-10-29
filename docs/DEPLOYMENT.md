# Theme package construction and deployment boundaries

This document describes the theme-only USB workflow tested with SMEG5.43.A.R2. It separates the source package, native installer, emulator validation, physical preparation and recovery limits. It does not establish a universal update procedure for other SMEG revisions or vehicles.

The expanded eight-theme installer passed native installation and a USB-free cold boot in a copied INT_E emulator fixture. That result does not certify physical NAND geometry, power-loss recovery or compatibility with every unit. The current physical test has not established that the six additional themes install successfully on the car.

## 1. Scope and inputs

The theme-only installer:

- Preserves the original SQUARE and WARMLIGHT compressed theme payloads.
- Adds GRAPHIC, ELLIPTIC, CUBIC, REFLEX, ESSENTIEL and REDLINE to two expanded resource banks.
- Copies six preview images, sets six native theme-enable flags and registers eighteen catalogue fields through native configuration APIs.
- Invalidates the generated `/SYSTEM_TMP_DATA/HarmoniesChecked.tst` catalogue cache marker.
- Backs up original data and reads back every installed theme payload before reporting success.
- Does not replace the application, BSP, whole SQLite databases or OS, enable Internet/PAN, install custom apps or reboot automatically.

The selected WARMLIGHT theme and unrelated settings were preserved in the tested fixture. ELLIPTIC and CUBIC still show minor clock/header overlaps. These are recorded limitations rather than a promise that every screen is visually complete.

Required private inputs are a legally obtained matching firmware update, its locally extracted resource and BSP files, a read-only original vehicle database export, a copied emulator seed and the generated asset/evidence manifests. None is supplied by a public clone. The experiment scripts retain phase-specific paths and refuse missing, stale or inconsistent evidence.

## 2. Extract and preserve originals

Follow [EMULATION.md](EMULATION.md) for package extraction and local filesystem preparation. Keep the supplied package unchanged. Preserve separate hashes of original exports before generating variants. A database export is not a complete NAND, bootloader or original application dump.

Relevant tools:

| Tool | Purpose |
| --- | --- |
| `scripts/extract_package.py` | ZIP path validation, extraction and file hashes |
| `scripts/extract_payloads.py` | Extract payloads from the supplied package |
| `scripts/inspect_sqlite.py` | Inspect local SQLite payloads |
| `scripts/smeg_db_inf.py` | Database compression/INF integrity encoding and verification |
| `scripts/theme_resource_format.py` | Convert/validate native theme bank representation |
| `scripts/backup_theme_readonly_return.py` | Copy an already mounted read-only export to host artifacts |

Do not copy another vehicle's or a factory profile's complete database into a physical unit to change a small number of flags. The native theme workflow uses bounded configuration setters instead.

## 3. Build the theme resource candidate

The assets are derived locally from the matching firmware. `prepare_all_theme_assets.py` inventories and constructs the initial banks. The theme-menu, dependency, style and layout preparation scripts record subsequent compatibility changes as manifests. The final tested asset directory was `artifacts/phase15/theme-assets/all-eight-layout-v8`.

These scripts are retained as research stages, not presented as one command that regenerates the whole historical asset/evidence tree. The expected input manifests and source hashes must exist before the final builder runs. Inspect the source and `--help` for each stage; do not substitute an unrelated asset directory or skip an assertion to get a build.

With those inputs available, the final source build is:

```sh
python3 scripts/build_usb_resource_probe.py \
  --output artifacts/phase20/complete-stock-moving-progress-v12 \
  --all-six --ported-menus \
  --assets artifacts/phase15/theme-assets/all-eight-layout-v8 \
  --erase-all-banks --complete-installer \
  --refresh-catalogue --register-catalogue --native-progress

python3 scripts/freeze_theme_installer_sources.py \
  --candidate artifacts/phase20/complete-stock-moving-progress-v12
```

The output must be new; the scripts intentionally refuse to overwrite prior candidate/evidence directories. Use a new candidate and matching test configuration for changed code. The builder requires Clang with its big-endian PowerPC backend, `mtools` and `dosfstools` (`mkfs.vfat`) in addition to the host prerequisites.

The virtual FAT32 image contains thirteen files:

```text
FLYING/
  doctor_smeg_plus_i.inf
  theme_resources.out
  theme_resources.out.inf
THEME_TEST/
  bank1.bin
  bank1.bin.inf
  bank2.bin
  bank2.bin.inf
PREVIEWS/
  theme1.jpg
  theme2.jpg
  theme3.jpg
  theme4.jpg
  theme7.jpg
  theme8.jpg
```

`theme_resources.out` is a native PowerPC relocatable module. The descriptor selects the existing maintenance load path. It is executable maintenance content, not a passive collection of pictures. CRC/INF validation detects mismatched content; it is not a vendor approval or cryptographic signature. See [REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md) for the separate RSA-OAEP contract findings.

## 4. Native installer ordering and progress

The wrapper in `emulation/usb_complete_themes_sandbox.c` combines the original-data export, bank writer, previews, flags, catalogue registration and cache invalidation. `usb_install_theme_resources_sandbox.c` and `theme_source_verify.h` implement the resource guards.

Before erasure, both bank payloads and both INF sidecars must each pass two consecutive full source checks. Original bank backups are also written and checked. The native write order is bank 2 followed by bank 1, then readback of all eight payloads. Publication of previews/flags/catalogue is gated on the resource result.

The native progress display reports measured verification/readback work and weighted phase completion. The flash erase and write APIs are synchronous and provide no per-byte callback: the bar deliberately holds a labelled stage during those operations. In the tested build it can remain at 52% while writing bank 2 and 66% while writing bank 1. This is not a simulated timer or a stalled animation.

Success is reported only after the full resource, preview, flag, catalogue and cache sequence succeeds. Original native popup text/progress state is restored after acknowledgement. A separate physical preflight can validate source reads and APIs without writing theme banks; it does not prove later flash-write success.

## 5. Validate the exact package in QEMU

The historical runners are:

```sh
bash scripts/run_theme_progress_install.sh
bash scripts/run_theme_progress_cold_check.sh
```

They require the documented private seed, candidate and earlier source evidence. They are not firmware-free smoke tests. Review their paths and runtime configuration before running a new candidate. Never pass a physical block device as the NAND or USB backend.

Acceptance requires all of the following:

1. Native USB insertion invokes the intended module and preflight completes before erasure.
2. Both native writes succeed and all eight payload CRC/readback checks pass.
3. The final receipt reports `COMPLETE_THEMES_RESULT status=0`; a screenshot alone is insufficient.
4. Resource/application preservation and all seven database/INF integrity audits pass, with no unexpected non-theme changes.
5. A cold boot from a private copy of the installed NAND, with no USB attached and no debugger RAM patches, shows all eight theme names and retains WARMLIGHT.
6. The source closure, rebuilt module and exact USB image are hash-bound to that evidence.

The production C fault harness additionally tests failure ordering without proprietary firmware:

```sh
mkdir -p artifacts/phase22
python3 scripts/test_theme_installer_failures.py \
  --out artifacts/phase22/public-release-fault-check
python3 scripts/test_theme_source_verify.py \
  --output artifacts/phase22/public-release-source-verifier.json
```

The tested V12 control-flow suite had 22 passing cases, including missing/corrupt INF rejection before erasure, write/readback failure handling and blocked publication. Host mocks do not certify hardware erase behavior. One native BSP erase wrapper does not return every underlying block-erase result; post-write readback is therefore essential.

The verified V12 USB image SHA-256 was:

```text
e4bcdbae7a4afbc05b5ba8f27ea7f577c9bd4b3115bc53e7443985ea55401c06
```

This identifies a local tested artifact; the image itself and private proof files are not distributed. A source or asset change invalidates reuse of this hash and its proof.

## 6. Prepare an explicitly identified USB

Physical preparation is opt-in. `scripts/prepare_progress_theme_usb.py` validates the candidate/evidence first. `--local-only` performs artifact checks without device inspection; the default additionally inspects the selected device read-only. Only `--write` writes a USB and requires administrator privileges.

The target identity comes from explicit environment variables or a private root `.smeg-local.json`, which is ignored by Git. Example structure, using values determined locally:

```json
{
  "usb_device": "/dev/disk/by-id/usb-YOUR_CONFIRMED_DEVICE",
  "usb_serial": "YOUR_CONFIRMED_SERIAL",
  "usb_capacity_bytes": 0,
  "usb_model": "YOUR_CONFIRMED_MODEL"
}
```

Replace the capacity with the actual byte capacity. Do not use guessed `/dev/sdX` names or sample identifiers. The writer checks the stable path, serial, model, capacity, removable/USB state, open descriptor and mount status; it refuses an unconfigured identity. The exact candidate is read from a held descriptor and rehashed. The current USB prefix is durably backed up before replacement; the full written image is read back and compared. Existing files must already have a separate verified host backup.

The physical writer also requires private preparation proof and prior physical read-only evidence. It is not a generic public flashing command, and its verification assertions must remain enabled. Use absolute paths when launching it through administrator tools; their working directory can differ from the shell's.

## 7. Physical theme-only test sequence

The following describes the prepared experimental installer, not an assertion that it works on an untested vehicle:

1. Park and keep the head unit reliably powered. Insert only the explicitly prepared, tested theme USB. The maintenance descriptor starts the installer automatically; SPYSTORE and an on-unit Start button are not required.
2. A brief normal media screen can precede the progress popup while original data is backed up. Do not interrupt the operation, press the popup's X, remove the USB or switch off the unit during erasure/writing. Labelled native-write stages can take several minutes.
3. Wait for the localized success message. Only then acknowledge X, allow the normal UI to return and remove the USB. There is no automatic reboot.
4. Fully shut down the head unit normally and restart without the USB. A rapid ignition off/on can retain the previous session and catalogue cache.
5. Open the normal theme selector and verify the new entries. Preserve the USB's generated `SMEG_BACKUP` logs for inspection.

The installer is intentionally one-use: the existing backup-directory guard prevents a repeat insertion from becoming an uncontrolled retry. If it reports failure, retain the stick and inspect its logs on the host. Do not remove that guard or repeatedly reinsert it to force another attempt.

## 8. Stock Restore and recovery limits

`scripts/build_stock_restore.py` constructs an **artifact-only restore candidate** from an original downloaded firmware package plus byte-exact exported database/INF pairs. Its scope must not be overstated:

- The seven live databases are original exports; the downloaded BSP/application are not a byte-exact physical binary dump.
- Stock Restore is a normal update-path candidate, not a bootloader recovery image or a complete NAND restore.
- It cannot force a non-running BootROM, U-Boot or native updater to read a USB.
- No hardware recovery button combination for this exact Peugeot 208 SMEG+ configuration has been verified by this project.
- The restore experiment is separate from the theme-only writer and is not automatically applied when a theme installation fails.

To construct the separate local candidate, with its expected original inputs present:

```sh
python3 scripts/build_stock_restore.py \
  --output artifacts/phase14/stock-restore/candidate/SMEG_PLUS_UPG \
  --image artifacts/phase14/stock-restore/stock-restore.raw
```

Keep any restore medium separate from experimental media and do not present it as a guaranteed fallback. Read its validation report and the corresponding native/cold-boot tests before considering it on hardware.

If the main screen becomes black or loops, this project supplies no validated force-recovery sequence. Preserve the package and logs, avoid arbitrary button combinations and repeated interrupted writes, and use an independently established recovery/service method for the exact unit. Never infer physical recovery capability from the direct-kernel QEMU boot path, which bypasses the real reset/bootloader chain.

## 9. Internet, custom apps and phone display mirroring

The theme-only package does not enable a Bluetooth network or install the separate INT_E binary/resource experiment. A visible Internet button does not establish DUN/PAN, DHCP, DNS, HTTP or browser compatibility. The loopback HTTP self-test did not show a browser request.

Local HTML/fuel-portal experiments are emulator demonstrations and remain separate scripts. The stock media player is not an Android MediaProjection receiver; no working phone-screen mirroring implementation is included. Do not bundle these experiments into a theme deployment or claim them as verified physical features.
