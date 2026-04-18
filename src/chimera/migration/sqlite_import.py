"""Import data from a legacy SQLite project DB into Postgres.

The source schema is the pre-migration chimera SQLite schema. Only tables
still present in the Postgres schema are copied; obsolete tables like
`findings` are silently ignored.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import asyncpg

from chimera.model.schema import PROJECT_TABLES


_TABLE_ORDER: tuple[str, ...] = (
    "binaries",       # must precede its children (FK targets)
    "functions",
    "call_graph",
    "strings",
    "permissions",
    "protections",
    "sdks",
)

_COLUMNS_BY_TABLE: dict[str, tuple[str, ...]] = {
    "binaries": (
        "sha256", "path", "format", "platform", "arch", "framework",
        "size_bytes", "package_name", "version", "min_sdk",
    ),
    "functions": (
        "binary_sha256", "address", "name", "original_name", "language",
        "classification", "layer", "source_backend", "decompiled",
        "signature", "ai_renamed", "ai_comments",
    ),
    "call_graph": (
        "caller_binary", "caller_addr", "callee_addr", "call_type",
    ),
    "strings": (
        "binary_sha256", "address", "value", "section", "decrypted_from",
    ),
    "permissions": (
        "binary_sha256", "permission", "declared", "actually_used",
    ),
    "protections": (
        "binary_sha256", "type", "product", "bypassed", "bypass_method",
    ),
    "sdks": (
        "binary_sha256", "name", "version", "package_prefix",
        "risk_level", "known_cves",
    ),
}

_CONFLICT_KEYS: dict[str, tuple[str, ...]] = {
    "binaries": ("sha256",),
    "functions": ("binary_sha256", "address"),
    "call_graph": ("caller_binary", "caller_addr", "callee_addr"),
    "strings": (),  # strings has no natural key; dedupe by id is meaningless post-import
    "permissions": ("binary_sha256", "permission"),
    "protections": (),
    "sdks": (),
}


def _rows_from_sqlite(
    sqlite_path: Path, table: str, columns: tuple[str, ...]
) -> list[tuple]:
    with sqlite3.connect(str(sqlite_path)) as conn:
        cursor = conn.cursor()
        tables_present = {
            row[0]
            for row in cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        if table not in tables_present:
            return []
        col_list = ", ".join(columns)
        return list(cursor.execute(f"SELECT {col_list} FROM {table}"))


def _coerce_row(table: str, row: tuple) -> tuple:
    """Convert SQLite-flavored values to Postgres types where needed."""
    # SQLite stores booleans as 0/1 integers.
    if table == "functions":
        row = list(row)
        row[10] = bool(row[10])  # ai_renamed
        return tuple(row)
    if table == "permissions":
        row = list(row)
        row[2] = bool(row[2])  # declared
        row[3] = bool(row[3])  # actually_used
        return tuple(row)
    if table == "protections":
        row = list(row)
        row[3] = bool(row[3])  # bypassed
        return tuple(row)
    return row


async def import_sqlite_to_postgres(
    sqlite_path: Path, pg_dsn: str
) -> dict[str, int]:
    """Copy each known table from SQLite into Postgres.

    Returns a dict of `{table_name: rows_inserted}`. Idempotent for tables
    with a defined conflict key; tables without a conflict key append on
    re-run (see `_CONFLICT_KEYS`).
    """
    if not sqlite_path.exists():
        raise FileNotFoundError(f"SQLite file not found: {sqlite_path}")

    report: dict[str, int] = {t: 0 for t in PROJECT_TABLES}

    conn = await asyncpg.connect(dsn=pg_dsn)
    try:
        for table in _TABLE_ORDER:
            columns = _COLUMNS_BY_TABLE[table]
            rows = _rows_from_sqlite(sqlite_path, table, columns)
            if not rows:
                continue
            rows = [_coerce_row(table, r) for r in rows]
            placeholders = ", ".join(f"${i+1}" for i in range(len(columns)))
            col_list = ", ".join(columns)
            conflict = _CONFLICT_KEYS.get(table, ())
            if conflict:
                conflict_list = ", ".join(conflict)
                assignments = ", ".join(
                    f"{c} = EXCLUDED.{c}"
                    for c in columns
                    if c not in conflict
                )
                sql = (
                    f"INSERT INTO {table} ({col_list}) VALUES ({placeholders}) "
                    f"ON CONFLICT ({conflict_list}) DO UPDATE SET {assignments}"
                )
            else:
                sql = (
                    f"INSERT INTO {table} ({col_list}) VALUES ({placeholders})"
                )
            async with conn.transaction():
                for row in rows:
                    await conn.execute(sql, *row)
            report[table] = len(rows)
    finally:
        await conn.close()

    return report
