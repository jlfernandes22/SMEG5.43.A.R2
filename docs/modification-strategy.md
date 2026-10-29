# Configuration work after extraction

> **Historical planning document.** Statements about unavailable firmware, databases, or execution evidence reflect this early phase. For the current consolidated findings and limits, start with [REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md) and [DEPLOYMENT.md](DEPLOYMENT.md).

This is a research plan, not an established feature-unlock procedure. No firmware,
SQLite database, or bench CAN capture has been supplied in this workspace.

## Source-backed leads

The [pepelxl configuration notes](https://github.com/pepelxl/psa-smeg-revers/blob/main/config_options.md)
locate software options at `/USER_DATA/user_data/sqlite/config_options.sqlite`.
They explicitly mix revisions: presence in these notes does not prove presence on
5.43.A.R2. `SW_OPTION_SMARTAPPS` is listed without a documented value or schema.
CarPlay (`SW_OPTION_IPOD_OUT`), Android Auto (`SW_OPTION_AAP`), and MirrorLink
are marked **SMEGIV2**, so these are not verified unlocks for this SMEG+ target.
Displaying an option cannot supply a missing protocol stack or required hardware.

The [up-config notes](https://github.com/pepelxl/psa-smeg-revers/blob/main/up-config.md)
list `internet / Smartapps` and navigation export settings. These are research
identifiers, not SQL column/table definitions. No verified Stop/Start switch has
been established here; a UI change must not be mistaken for engine ECU behavior.

The [README](https://github.com/pepelxl/psa-smeg-revers) describes dosFs volumes
and automatic database recovery from `/USER_DATA_BACKUP`, then system defaults.
That recovery logic may replace an altered database. The `SMEG_extarct_harm`
utility is for theme containers, not a complete firmware unpacker.

## Reproducible next actions

1. Preserve firmware hashes and obtain the extracted files with provenance.
2. Inspect a database copied from the extracted image:

   ```bash
   python3 scripts/inspect_sqlite.py /absolute/path/config_options.sqlite > artifacts/config-schema.json
   ```

   This opens SQLite in read-only mode and outputs schema plus SHA-256; it never
   executes SQL supplied by the database or changes option values.
3. Identify actual table names, keys, types, value meanings, triggers, and firmware
   call sites. Check whether another flag, signature, or backup overrides the value.
4. Use SQLite's backup API to make a working copy if a live database has a WAL.
   Apply a parameterized UPDATE only after the exact schema and target row are
   known; assert one affected row in a transaction, then check integrity and diff.
5. Modify one UI/theme/configuration behavior at a time in the offline working
   copy and validate through a function harness or emulator when available.

Exact UPDATE/injection statements are deferred until an actual schema is present.
Inventing `options(name,value)` would produce an unreviewable change and may not
match this firmware at all. No write-back or flashing commands are supplied.
