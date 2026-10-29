# Reverse engineering of SMEG+ 5.43.A.R2

This document consolidates findings from static analysis of a locally supplied SMEG+ 5.43.A.R2 update package and controlled execution of its software in the project's emulator. It describes the evidence supporting each conclusion, the experimental conditions, and the remaining uncertainties. It is a research account, not a procedure for installing modified software on a vehicle.

The central result is that the inspected package targets a 32-bit, big-endian PowerPC platform with an MPC5121E/e300 board support package and VxWorks 6.7. Application analysis identifies independent configuration, hardware-profile, and graphical-resource conditions affecting the Internet interface. Later emulator experiments demonstrate persistent installation and display of that interface under the tested model. They do not demonstrate a physical Bluetooth DUN/PAN session, external Internet access, or reliable recovery of a physical unit.

## 1. Scope and evidence conventions

The principal input is an extracted `SMEG_PLUS_UPG` package whose variant metadata identifies `SMEG5.43.A.R2` and whose media version is `26482`. The package contains `NAV`, `AUDIO_BT`, and `AUDIO_BT_256` application variants, separate 256 and 512 BSP variants, graphical resources, update modules, and default data. Variant names are package identifiers; their presence does not identify a particular installed unit.

Four kinds of evidence are distinguished throughout:

| Evidence | What it establishes | Principal limitation |
| --- | --- | --- |
| File structure, headers, hashes, and checksums | Properties and internal consistency of the inspected package | Does not establish vendor provenance, physical installation, or execution |
| Symbols and disassembly | Data references, instructions, and control flow in a specific binary | Names and individual branches do not establish a complete feature or protocol |
| Instrumented emulator execution | Behavior of original guest code with the recorded inputs and model | Depends on boot assumptions, modeled peripherals, fixtures, and any experimental changes |
| Physical observation | Behavior of the observed physical unit under recorded conditions | Cannot be inferred from the other three categories |

The findings below use the first three categories. Existing local exports were used as inputs to some experiments, but their values are not published here. No physical device was accessed while preparing this document. An emulator result is labeled explicitly where it bears on a capability claim.

Addresses require particular care. A **file offset** is a zero-based position in a file. A **runtime address** belongs to the loaded guest address space. A **manifest update address** is a destination interpreted by the updater. These quantities are not interchangeable. All offsets in the platform table below are file offsets; application instruction addresses in later sections are runtime addresses for the fingerprinted build.

Some earlier phase documents record the state of knowledge before package extraction or before later successful experiments. Their statements that a sample or boot was unavailable are historical. This document incorporates the later evidence without extending its scope to physical hardware.

## 2. Platform identification

### 2.1 Instruction set and operating system

Independent ELF-header decoding and `readelf -h` identify `upgrade.out`, `upgrade_256.out`, `upgrade_lib.out`, `UpgPlugin.out`, and `NAV/DB_DWNL/db_dwnl_gl.out` as ELF32, big-endian, PowerPC (`EM_PPC = 20`) relocatable objects (`ET_REL = 1`) with entry value zero. These are loadable modules requiring relocation and symbol resolution, rather than standalone kernel images. The generic System V ABI field is not evidence of Linux or QNX.

Both supplied `vxWorks.bin` files contain VxWorks 6.7, MPC5121E ADS, and e300 literals:

| Observation | `SMEG_PLUS_256` | `SMEG_PLUS_512` |
| --- | --- | --- |
| File length | 6,713,760 bytes | 6,713,840 bytes |
| CRC32 | `731ae273` | `71242c66` |
| First `VxWorks 6.7` literal | `0x308a40` | `0x308b80` |
| `Freescale MPC5121E ADS` literal | `0x5174cc` | `0x51761c` |
| e300 core diagnostic | `0x517918` | `0x517a68` |

The kernels begin with plausible big-endian PowerPC instructions, rather than an ELF or gzip header. Their readable code, symbol records, and OS strings provide substantially stronger identification than an incidental magic match from a generic file-identification utility. The `VxWorks Edition for ppc603` string is consistent with the compiled PowerPC target and does not independently identify a different physical processor.

Together, these observations establish the compiled platform target as MPC5121E/e300 with VxWorks 6.7. NXP's [MPC5121e product documentation](https://www.nxp.com/products/MPC5121e) independently describes an e300 processor core and a separate AXE audio accelerator. That architecture does not support describing AXE as a second PowerPC CPU. Neither the BSP banner nor the product's maximum specification measures an installed unit's clock rate, RAM, NAND, or board revision.

The read-only inventory tool is [inspect_firmware.py](../scripts/inspect_firmware.py). Detailed package observations are retained in [phase2-platform-verification.md](phase2-platform-verification.md). The firmware itself and its extracted symbol maps are required local inputs, not documentation assets.

### 2.2 Boot evidence and the emulation entry point

The updater contains BootRom and U-Boot version and update diagnostics, including references to `u-boot-nand.bin`. The inspected package does not contain a separately named U-Boot image. A string describing an optional updater stage does not supply the installed loader, its environment, or a complete reset sequence.

Subsequent analysis in [derive_boot_layout.py](../emulation/derive_boot_layout.py) relates contiguous VxWorks symbol records and their pointers to a kernel load base of `0x00200000`. It identifies `_sysInit` and the initialization path to `usrInit`; the emulator uses the kernel initialization entry rather than reproducing the physical initial bootloader. This is a supported experimental entry point, not a measured physical reset vector.

For the supplied manifests, kernel update addresses are `0x420000` for the 256 BSP and `0x720000` for the 512 BSP. Both `dbsystem.bin` records are 40 bytes at manifest update address `0x180000`. Their first words reproduce the corresponding kernel destination, size, and CRC32, and their final word matches CRC32 of the preceding 36 bytes. This establishes those record relationships, not a complete flash-layout specification. In particular, the kernel update addresses are not runtime load bases. Further storage evidence is documented in [phase2-boot-layout.md](phase2-boot-layout.md).

## 3. Package, application, and storage formats

### 3.1 Archives and application containers

The files named `system.bin` are gzip-compressed tar archives containing application modules, defaults, portal assets, and other resources. `system_data.bin` contains the SSM boot module and its sidecar. An update archive is not a raw NAND dump, a complete disk image, or a direct representation of physical partition allocation.

Each inspected `f_BigQuick.bin` contains a 2 KiB table of 64 records, two used records, and 62 records filled with `0xdeadbeef`. Two zlib streams are present. The first starts after the marker at `0x800`; the second is located using the next record's block index. Inflated lengths match the table, and both streams reach their end markers. The first stream is followed by a two-byte suffix and `0xEE` alignment padding before the second stream. Later analysis verifies the suffix as the native one's-complement checksum over the marked compressed stream, with residue `0xffff` after including the suffix.

This second segment is significant: a repacker which retains only the first stream can produce a structurally incomplete application even when that first stream decompresses successfully. [inspect_app_data.py](../scripts/inspect_app_data.py) audits both segments; [patch_int_e_candidate.py](../scripts/patch_int_e_candidate.py) preserves them, checks source fingerprints and expected instructions, and verifies the reconstructed container. Its local container checks are distinct from acceptance by the complete updater.

The recorded runtime bases are `0x01000000` for the main application and `0x04c00000` for the second segment in the relevant experiments. The latter was used only with matching runtime instruction fingerprints. A container offset alone is insufficient to establish a segment's runtime address.

For extraction, [extract_package.py](../scripts/extract_package.py) validates ZIP paths and records hashes, while [extract_payloads.py](../scripts/extract_payloads.py) handles the known gzip/tar and main BigQuick payloads. It does not replace the two-segment audit. The more detailed inventory is in [phase2-app-data.md](phase2-app-data.md).

### 3.2 Default, live, and generated databases

The package's default SQLite databases are separate from databases stored in `/USER_DATA`, their `/USER_DATA_BACKUP` counterparts, and temporary or generated configuration. Editing an update default is therefore not evidence that an existing live setting has changed. A generated hardware-profile value can also be recomputed on boot.

In the inspected defaults, `config.sqlite/config_system` and `config_options.sqlite/sw_option` have no rows. `up_config.sqlite` contains a typed `UP_Keys` schema with key `(Section, Name, Idx)` and distinct integer, float, string, and blob columns. This is not a generic two-column name/value store. The default configuration contains `internet/Smartapps`, but a stored name and value alone establish neither hardware support nor working behavior.

Native runtime SQLite files can be gzip-wrapped and accompanied by `.inf` metadata. [smeg_db_inf.py](../scripts/smeg_db_inf.py) implements the recovered gzip-VFS form using the firmware's native CRC16 tables. It checks the metadata CRC, uncompressed-data CRC, logical size, and decompression result. Its supported format does not establish an equivalent sidecar format for every raw, unwrapped database. Database validation must account for the particular storage form and its consumer.

## 4. Integrity, the media contract, and authenticity

### 4.1 Several integrity mechanisms coexist

The observed update path combines several checks, with different purposes and coverage:

| Mechanism | Observed coverage | Defensible interpretation |
| --- | --- | --- |
| Native CRC16 `.inf` metadata | Metadata and selected payloads, including executable sidecars | Internal checksum consistency |
| CRC32 manifests and control files | Payloads, archive entries, module/root control cascades | Internal consistency across the package |
| zlib checks and native stream suffixes | Compressed BigQuick segments | Stream integrity and container-format consistency |
| Version and compatibility logic | Media/product comparisons and component compatibility | Admission conditions in the inspected code path |
| RSA-OAEP media contract | Encrypted records checked against package members | An additional encrypted contract format, characterized below |

The local original-package audit verifies CRC16 metadata and content for three native executable sidecars and trailing CRC32 values for 16 control files. The database VFS checksum and the update control-file checks must not be conflated simply because both use `.inf` or CRC terminology. Recomputing a checksum can restore structural consistency after an edit; it does not establish cryptographic authenticity or vendor approval.

### 4.2 What the RSA discovery establishes

The native call chain includes `LoadUpgradePlugin`, `CheckTrustedSource`, `RsaHeaderDecrypt`, `RsaReadDataBlockDecrypt`, and `C_ENG_CRYPTO::RsaDecrypt`. The inspected implementation calls private RSA decryption with OAEP padding; associated padding code uses SHA-1 and MGF1. The native initialization path constructs RSA values from embedded data.

The read-only [analyze_updater_integrity.py](../scripts/analyze_updater_integrity.py) audit discovers candidate embedded RSA parameters in the locally extracted application, verifies the matching private-exponent relation, decrypts the contract in memory, and compares its records against the original package. The recorded aggregate result is:

| Property | Recorded result |
| --- | --- |
| Matching RSA modulus length | 2048 bits |
| Public exponent | 65537 |
| Unique embedded RSA moduli found | 2 |
| Decrypted header length | 152 bytes |
| Contract records checked | 115 of 115 match |
| Check types | 13 size, 84 CRC32, 18 byte-range records |

This is evidence of recoverable private-decryption material and a working characterization of this package's contract. It is not evidence that a vendor signing key has been recovered. The encryption direction matters: [RFC 8017, sections 7 and 8](https://www.rfc-editor.org/rfc/rfc8017.html#section-7) distinguishes RSA encryption schemes, including RSAES-OAEP, from RSA signature schemes. The observed OAEP private-decrypt/public-encrypt format must not be renamed a vendor digital signature merely because some upstream tooling uses “signed” or “re-sealed” terminology.

The audit emits aggregate verification results. It does not save RSA private parameters or plaintext contract records. This document contains neither. Its conclusions are deliberately limited to the inspected contract and call chains: physical OTP/fuse configuration, an immutable hardware root of trust, the initial bootloader, and any other authentication mechanism have not been comprehensively verified. Contract-format compatibility does not establish their absence or defeat.

## 5. Internet eligibility and resource experiments

### 5.1 Independent policy conditions

[analyze_int_e_patch.py](../scripts/analyze_int_e_patch.py) compares fingerprinted `AUDIO_BT_256` and `NAV` applications. Both contain the same conditional INT_E exclusion in the Desktop Internet-availability calculation. A working NAV control therefore does not show that NAV lacks this condition; its hardware-profile inputs differ.

The second application segment contains an independent backend condition. In the inspected Audio build, `IsRamSizeLimited` obtains `HW_FLAG_SMEG_INT_E` through `C_CONFIG_SYSTEM::GetValue`. Despite its name, the observed result is consequently a hardware-profile policy read, rather than a measurement proving that the guest has exhausted physical RAM. Supplying 512 MiB to an emulator does not by itself clear that policy or establish suitability for a smaller physical device.

The typed `internet/Web_active` preference is another prerequisite. Early RAM experiments found that removing only the Desktop INT_E exclusion left Web unavailable with the original `Web_active=0`. In a separate native-API experiment, saving `Web_active=1` survived cold boot but the unmodified INT_E backend still returned Web unavailable. These observations distinguish preference persistence from full feature availability.

The early diagnostic changes were fingerprint-guarded writes to loaded application RAM in QEMU. Source firmware files and protected input copies were audited separately. A native maintenance-module attempt to reproduce the application-text store raised a data-access exception; it did not demonstrate deployment of those debugger patches through USB. The experimental matrix and its limits are summarized by [summarize_int_e_patch.py](../scripts/summarize_int_e_patch.py) and [summarize_usb_capabilities.py](../scripts/summarize_usb_capabilities.py).

### 5.2 `m_force_no_dun_management`

The field analyzed under the name `m_force_no_dun_management` is a byte at object offset `0xba` in `C_BCM_BT_AGENDA`. Both observed constructor variants initialize it to one. A controlled candidate changes the source register of the constructor store to a register verified to contain zero. An earlier suggested address, `0x0182d338`, is a different instruction and is preserved by the guarded builder.

Cross-references occur in Agenda status buffering and `HandleMessageDUN`. They support an Agenda-specific DUN-event policy interpretation. They do not establish that the byte globally enables or disables every DUN/PAN transport or Internet path. Setting the field to zero alone did not unlock the browser in the early experiment.

Later native eligibility and resource controls displayed the Internet secondary menu while this Agenda field remained one. Thus clearing it is not necessary for that particular menu-rendering result. The later persistent candidate also demonstrates the modified initialization producing false after cold boot, but still does not demonstrate a live DUN/PAN session. These are compatible findings: menu visibility, handler policy, and successful network transport are different observations.

### 5.3 Graphical resources explain an additional failure mode

The native GUI requests Internet application `8`, screen `3`, for the secondary menu. Inspection of the compiled resource directories finds that the tested Audio resources lack 23 Internet windows present in their NAV counterparts, including screen 3. Clearing policy conditions can therefore leave a visible main-menu tile followed by an incomplete or black content area.

[inspect_internet_harmony.py](../scripts/inspect_internet_harmony.py) verifies resource checksums and window directories and can create an explicitly emulator-only control. That control substitutes the whole original NAV SQUARE compiled resource into a disposable NAND image while retaining the Audio bank selection. With the native eligibility refresh, the emulator displays “Internet browser”, “Transfer rate”, and “Internet connection settings”. A normal-boot-then-virtual-USB-insertion control also displayed that menu. The Agenda flag remained one, and the readiness/PPP state remained zero.

This control is not a minimal merge of 23 windows: it brings unrelated NAV layouts with it. The corresponding traces also contain startup/timing and missing-vehicle-state warnings. Their evidentiary value is the observed resource and menu behavior under those conditions, not certification of a complete, clean vehicle startup. [summarize_usb_network.py](../scripts/summarize_usb_network.py) records this distinction and the cold-boot recomputation of the INT_E profile after the temporary native-API changes.

### 5.4 Later persistent installation result

The work progressed beyond the early RAM-only controls. The recorded candidate-v5 experiment completed a native emulator update, stopped the virtual machine for an installation audit, and cold-booted without virtual USB. It reported no debugger RAM changes, verified the intended loaded policy, and displayed the native Internet secondary menu. The retained settings audit matched all seven exported database contents against the candidate after cold boot.

Its conditions materially limit generalization. The harness supplied an unchanged original 256 BSP kernel externally at `_sysInit`, while the model used 512 MiB RAM and 512 MiB NAND data capacity with 2048-byte pages and 64-byte spare areas. Both SQUARE and WARMLIGHT resources were complete NAV-derived payloads within Audio bank headers. The result therefore establishes persistence in that model, not memory sufficiency or boot compatibility of a physical INT_E unit. Exact candidate-v5 used the native recovery entry; the normal UI confirmation path was separately tested with candidate-v4. Those paths should not be described as an identical end-to-end test of every candidate.

The later idle image returns to the Connect Apps landing page; the evidence does not show the secondary menu remaining permanently open. No live Bluetooth DUN/PAN session or external Internet traffic was verified. The relevant builders and audits include [patch_int_e_candidate.py](../scripts/patch_int_e_candidate.py), [build_franken_candidate.py](../scripts/build_franken_candidate.py), and [audit_persistent_candidate.py](../scripts/audit_persistent_candidate.py). Their experimental names are not product-support claims.

## 6. Browser execution is separate from network access

The local browser-content experiments demonstrate HTML, JavaScript, touch interaction, external JavaScript files, SVG, canvas readback, relative and `file:` resource retrieval, and session local-storage access for individually tested cases. A native JSON parser was not available in the tested case; the original portal includes a JSON compatibility shim. Native read-only clock and vehicle/trip getters were observed, but the vehicle values came from emulated ECU fixtures. Static metadata listing a binding is weaker evidence than an observed call.

These local-content results do not establish an operational online service. A normal USB storage device is not thereby a stock Internet network adapter. The browser/network diagnostic in [simulate_browser_network.py](../scripts/simulate_browser_network.py) provides a useful further distinction:

- The native readiness gate initially reported no connected modem-mode Bluetooth device and PPP state zero.
- An explicitly labeled runtime simulation changed object data to exercise a ready state. It did not establish a negotiated Bluetooth link.
- A separate native socket client and server exchanged a verified HTTP response over guest loopback at `127.0.0.1`. This proves that socket/HTTP self-check in the guest.
- The browser did not issue the diagnostic page request, and the expected canary HTML was not visibly rendered. The socket self-check was not a browser request.

Consequently neither a visible menu, simulated readiness, nor a successful loopback self-check proves external Internet access. The unresolved browser URL-dispatch or widget-initialization path also does not, by itself, establish missing hardware or a fundamental inability to implement a feature. CarPlay, Android Auto, navigation activation, engine Stop/Start behavior, and other vehicle controls have not been established by these Internet experiments.

## 7. Emulator validity and recovery limits

The project includes a custom QEMU machine in [mpc5121e_smeg.c](../emulation/mpc5121e_smeg.c), the [launch harness](../emulation/launch.sh), peripheral models, and test fixtures. It executes supplied guest software, but its boundary conditions must accompany every result. The launcher selects `smeg-mpc5121e`, an e300c4 CPU model, a single emulated CPU, and explicit RAM and storage inputs. It supplies the BSP externally. The default software GLES path translates guest graphics calls through host rendering while the MBX draw engine remains incomplete. Front-panel MCU and vehicle-state fixtures are modeled inputs.

“Cold boot” in these reports means restarting guest execution against the retained virtual storage rather than resuming guest RAM. It does not mean that the physical BootROM, U-Boot, reset straps, power sequencing, NAND faults, or initial loader have been reproduced. A native guest update is stronger evidence than an offline file replacement for the tested updater path, but it remains conditional on the model and the exact image.

The inspected code contains multiple recovery-related paths: application loading of the upgrade plugin and media contract, BSP recovery loading, and maintenance-module handling. They have different entry conditions and dependencies. The maintenance mechanism can execute code or rename boot-related files; its presence must not be summarized as an inherently read-only export facility.

[build_stock_restore.py](../scripts/build_stock_restore.py) and the [cold-boot restore test](../emulation/test_stock_restore_cold_boot.py) provide controlled emulator restoration work. Byte comparisons, virtual-media readback, and a successful modeled restore do not prove a physical fail-safe recovery. In particular, recovery still requires a reachable and functioning loader/BSP/updater path; it has not been demonstrated after initial-loader corruption, incompatible hardware state, power interruption, or physical flash failure. There is no supported claim of a universally safe bypass or guaranteed recovery.

## 8. Reproduction and publication boundaries

Reproduction requires an independently obtained matching firmware package, the expected local directory layout, and each script's dependencies. The original inputs should be hashed before extraction, kept separate from generated files, and compared again after experiments. Variant, kernel, resources, RAM/NAND model, renderer, boot method, API fingerprints, runtime edits, and fixture state should be recorded together. Screenshots should be paired with traces and stopped-storage audits; a screenshot alone cannot establish persistence or network transport.

For initial inspection, the following commands read package contents without executing firmware:

```sh
python3 scripts/inspect_firmware.py /absolute/path/SMEG_PLUS_UPG
readelf -h /absolute/path/SMEG_PLUS_UPG/upgrade.out
python3 scripts/inspect_sqlite.py /absolute/path/copied-default.sqlite
```

The integrity audit uses a new output file under its fixed local analysis directory:

```sh
python3 scripts/analyze_updater_integrity.py \
  --output artifacts/phase14/security-analysis/new-audit.json
```

These examples are inspection commands, not an installation sequence. Scripts that build candidates, rewrite virtual storage, launch the emulator, access Bluetooth hardware, or prepare physical media have additional side effects and should be assessed individually; they are not needed to read this document.

Public evidence should consist of original analysis, reproducible scripts, bounded non-sensitive observations, and aggregate verification results. Vendor firmware, extracted proprietary binaries or symbol maps, decrypted contract contents, RSA private parameters, physical-unit exports, personal databases, identifiers, credentials, and unredacted logs require separate exclusion from a public source release. The absence of such material from this document is not a claim that every generated local artifact has been cleared for publication.

## 9. Upstream attribution

The research builds on the primary reverse-engineering work in [pepelxl/psa-smeg-revers](https://github.com/pepelxl/psa-smeg-revers), including the Harmony extractor and configuration notes, and [KRoperUK/smeg-plus-patches](https://github.com/KRoperUK/smeg-plus-patches), including extraction, symbols, package-checking, and contract tooling. The recorded early local source snapshots were respectively `932db83c6e1518f5b9ddf3050670ab218329ec68` and `c5eda38e6b5520015bbbd59bde8caf97c2e4fb7c`; later upstream content may differ.

Those projects supply valuable hypotheses and tools. Where their terminology or hardware summaries differ from the package observations, this document follows the directly inspected headers, instructions, and experimental controls. NXP's [MPC5121e reference manual](https://www.nxp.com/docs/en/reference-manual/MPC5121ERM.pdf) is the primary architectural reference; [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017.html) supplies the cryptographic scheme terminology. Neither source certifies the project's emulator or a modified update for use on physical hardware.
