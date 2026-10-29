#!/usr/bin/env python3
"""Inventory a supplied SQLite DB without executing SQL from its contents or writing it."""
import argparse
import hashlib
import json
import sqlite3
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    args = parser.parse_args()
    path = args.database.resolve(strict=True)
    digest = hashlib.file_digest(path.open("rb"), "sha256").hexdigest()
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as conn:
        conn.execute("PRAGMA query_only=ON")
        conn.execute("PRAGMA trusted_schema=OFF")
        schema = conn.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name"
        ).fetchall()
        tables = []
        for kind, name, table, sql in schema:
            entry = {"type": kind, "name": name, "table": table, "sql": sql}
            if kind == "table":
                entry["columns"] = [
                    dict(zip(("cid", "name", "type", "notnull", "default", "pk"), row))
                    for row in conn.execute("SELECT * FROM pragma_table_info(?)", (name,))
                ]
            tables.append(entry)
    print(json.dumps({"path": str(path), "sha256": digest, "schema": tables}, indent=2))


if __name__ == "__main__":
    main()
