# Physical theme installation and logo incident

Reported 29 October 2026 for the project's Peugeot 208 with SMEG5.43.A.R2.

The owner reported that the V12 theme installer completed successfully, followed by a persistent Peugeot logo after restarting with the used installer USB still inserted. The car later booted normally with new themes visible after a period switched off. This recovery occurred **before the prepared reset-only USB was used**. No physical test of that helper occurred.

This is one owner's physical test report, supported by an offline inspection of the returned USB. It establishes neither compatibility with other units nor a guaranteed recovery procedure. The new themes were reported visible; all eight themes were not individually selected and checked on the physical unit.

## Physical observations

| Stage | Owner's report | Limit of the observation |
| --- | --- | --- |
| Installation | The V12 installer displayed success. | The returned receipts provide separate evidence of the installer results below. |
| Restart with used USB present | The screen remained on a static Peugeot logo for about five minutes. Removing the USB did not restore the normal UI in that session. | No physical boot trace was captured. |
| Further restart attempts | A SRC + MENU reset did not restore the UI. The owner also reported a natural display switch-off followed by another USB-free restart that still showed the logo. | These observations do not establish that power to the head unit's CPU was fully removed. The button action is recorded as an observation, not a recovery instruction. |
| Later attempt | After a period with the car switched off, the unit started normally and new themes were visible. | Approximately 1.5 hours elapsed between the failure report and the next successful attempt; this was not a measured continuous power-off interval or a measured recovery time. |
| Reset-only helper | A separate helper USB had been prepared, but the normal boot occurred before it was used. | Physical helper execution and physical helper recovery remain untested. |

The owner subsequently suggested that perhaps 30 minutes with the car completely off might suffice. **Thirty minutes is an unverified suggested observation period**, not a measured minimum, guaranteed fix or OEM procedure. No exact shutdown interval or recovery threshold was established.

## Returned USB evidence

The used installer USB was inspected read-only and its 43 files were copied and hash-verified for local preservation. No further car write was part of that inspection. The returned receipts recorded:

- `COMPLETE_THEMES_RESULT status=0`, with resource installation, previews, flags, native catalogue registration and catalogue cache invalidation all reporting status 0.
- Successful native writes of both resource banks and verified CRC/readback results for all eight installed payloads.
- Verified original SQUARE and WARMLIGHT resource backups. Their payloads and entry headers matched the original matching firmware package.

These results support successful completion of the installation pipeline and preservation of the original resource backups. Payload verification does not establish that every theme renders correctly on every physical screen, or that a unit will recover from an interrupted write. The later normal boot and visible themes are owner observations rather than an independently captured physical UI audit.

Private USB exports, firmware, databases, logs and proof files remain outside the public repository. This report summarizes the relevant findings without distributing those artifacts.

## Emulator reproduction and explanation

QEMU reproduced a logo stall when the used V12 installer USB was present at boot. The same installed NAND fixture booted to the normal FM UI without the USB. Removing the used USB after the stall did not start the UI in that existing session.

Static analysis of the original BSP and SSM boot code explains the emulator result. Detection of the maintenance descriptor invokes the native BSP/SSM callback before the installer module runs. That callback sets a RAM flag which makes SSM skip the application entry point. The used installer then reaches its existing-backup repeat guard and aborts. The guard prevents another installation, but it runs after the native startup decision. Removing the USB does not replay the application entry that SSM already skipped.

This is a supported explanation of the reproduced emulator behavior and a plausible explanation of the physical symptoms. It does not prove the physical unit's cause, exact RAM state or power-management behavior.

A separate, exact reset-only helper was tested in QEMU both from a cold start and by hotplug after reproducing the used-USB logo stall. After helper USB removal, the native `EmergencyReboot` path reset the modeled unit and the normal FM UI returned; theme resource ranges remained byte-exact. No debugger RAM or instruction patches were used for those tests. QEMU models the reset path, so this evidence does not validate physical electrical reset or recovery. It cannot explain the owner's later recovery as a helper result because the helper was not used in the car.

## Deployment implications

**Remove the installer USB after confirmed completion and before any restart.** Keep its generated backup and receipt files intact. The one-use guard is not protection against the native maintenance boot path being entered with the used stick present.

If the logo persists after a completed installation, stop repeating resets or reinserting the installer. Preserve the observations and returned USB logs. A normal, extended car-off period with the installer removed can be observed and recorded, but this report supplies no guaranteed duration or force-recovery procedure. This observation applies only after installation has completed; it is not an instruction to interrupt erasure or writing.

If normal startup has returned, no reset-only helper is needed. Keep active maintenance media out of the car, and remove its maintenance entry files before reusing the stick as ordinary media. Read the [risk and liability notice](../DISCLAIMER.md) before further hardware experiments.

See [DEPLOYMENT.md](DEPLOYMENT.md) for the package workflow and recovery boundaries, and [EMULATION.md](EMULATION.md) for the emulator's scope. The successful later boot does not establish power-loss rollback, a complete physical backup or a universally safe installation.
