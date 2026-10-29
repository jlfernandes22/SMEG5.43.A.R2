# Contributing

Keep changes reproducible and separate platform assumptions from observations.

## Development

Read [EMULATION.md](docs/EMULATION.md) and [REVERSE_ENGINEERING.md](docs/REVERSE_ENGINEERING.md) before changing the board model or native update code. Use a copied NAND image for experiments. Keep original packages and vehicle exports unchanged.

Describe the firmware build, BSP/profile, emulated RAM/NAND configuration, relevant source revision, command line and expected result. Include a minimal serial-log excerpt with personal data removed. A startup logo, database flag change or successful loopback HTTP test does not prove that the intended application screen or network path works.

Run checks appropriate to the change. For native installer changes, include pre-erase error handling, both bank-write attempts, readback, failure publication guards and USB-free reboot evidence. A change to a tested source closure requires rebuilding and retesting the exact candidate; do not reuse an older package proof.

## Publication boundaries

Do not commit firmware bundles, extracted proprietary payloads, live SQLite databases, Bluetooth pairing material, VINs, device identifiers, credentials, private RSA parameters or raw media. The ignore rules are a convenience, not a substitute for reviewing `git diff --cached`.

UI screenshots may document behavior but must not expose personal data or be presented as openly licensed replacement assets. Keep third-party source notices and provenance intact.

## Reporting physical results

Clearly label a result as static analysis, emulator testing or physical observation. Report failures and incomplete behavior as well as successful screens. Do not claim a recovery button combination, universal hardware compatibility or successful networking without direct evidence for that exact configuration.
