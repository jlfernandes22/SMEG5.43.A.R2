# Third-party notices

Project-authored code is licensed under GPL-2.0-or-later unless an individual file states otherwise. Existing third-party notices take precedence for their respective files. The root LICENSE contains the GPL version 2 text; the project grants the option to use later versions.

## QEMU

The custom machine and integration code target QEMU 9.2.0 at commit `ae35f033b874c627d81d51070187fbf55f0bf1a7`. QEMU is obtained separately from [qemu/qemu](https://github.com/qemu/qemu), and its source tree is excluded from this repository. Retain QEMU's own LICENSE, COPYING and component notices when building or redistributing a combined emulator. This release distributes the machine source and integration scripts, not a prebuilt QEMU executable.

## U-Boot NAND reference

`emulation/reference_nfc.c` is a reference copy of the MPC5121 NFC driver from U-Boot v2010.12, with its original copyright and GPL notice retained. It is not compiled into this emulator. Source URL, SHA-256 and interpretation notes are recorded in `emulation/reference_nfc.provenance.json`.

## PowerVR texture decompression

`emulation/powervr/PVRTDecompress.cpp` and `PVRTDecompress.h` originate from the PowerVR Native SDK at commit `63f0098acdc11ec9a072c30000d2fa670a955bee`. Their MIT license is preserved in `emulation/powervr/LICENSE.txt`; source URLs and hashes are in `emulation/powervr/provenance.json`. Other project graphics code is covered by its own file notices or the project license.

## Khronos interfaces

The graphics bridge uses EGL and OpenGL headers/interfaces from the host development packages and, in historical experiments, separately obtained Khronos registry files. External headers are not bundled. Their respective upstream licenses apply.

## Research references

The local analysis used [morluto/rea](https://github.com/morluto/rea), [pepelxl/psa-smeg-revers](https://github.com/pepelxl/psa-smeg-revers) and [KRoperUK/smeg-plus-patches](https://github.com/KRoperUK/smeg-plus-patches). Their checked revisions are recorded in `sources.lock.json`. These are separate upstream projects; this repository does not relicense or distribute their complete checkouts.

## Proprietary material

SMEG firmware, VxWorks, proprietary applications, theme banks and original vehicle databases are not included or licensed by this project. Obtain required inputs independently. Selected emulator UI screenshots are included only to document research results and remain subject to the rights in the depicted software, artwork and trademarks. They are excluded from the project code-license grant.
