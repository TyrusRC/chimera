"""A8: FunctionInfo.sources now persists through the functions table.

The real DAL uses asyncpg/Postgres (covered by the integration suite). Here we
prove the encode/decode contract and a full round-trip through a TEXT column
using stdlib sqlite3 — the same shape `ChimeraDatabase.save_function` /
`load_functions` rely on, verifiable without a live DB.
"""

from __future__ import annotations

import sqlite3

from chimera.model.function import FunctionInfo
from chimera.model.serialize import decode_sources, encode_sources


def test_encode_decode_round_trip():
    assert decode_sources(encode_sources(["radare2", "ghidra"])) == ["radare2", "ghidra"]
    assert decode_sources(encode_sources([])) == []
    assert decode_sources(encode_sources(None)) == []


def test_decode_tolerates_bad_input():
    assert decode_sources(None) == []
    assert decode_sources("") == []
    assert decode_sources("not json") == []
    assert decode_sources('{"k": 1}') == []      # object, not a list
    assert decode_sources(["radare2"]) == ["radare2"]  # already-decoded passthrough


def test_sources_survive_column_round_trip():
    func = FunctionInfo(
        address="0x1000", name="main", original_name="main", language="c",
        classification="unknown", layer="native", source_backend="radare2",
    )
    func.sources = ["radare2", "ghidra"]

    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE functions (address TEXT, sources TEXT)")
    # Mirror save_function's write path:
    conn.execute(
        "INSERT INTO functions (address, sources) VALUES (?, ?)",
        (func.address, encode_sources(func.sources)),
    )
    # Mirror load_functions' read path:
    row = conn.execute(
        "SELECT sources FROM functions WHERE address = ?", (func.address,)
    ).fetchone()
    restored = decode_sources(row[0])

    assert restored == ["radare2", "ghidra"]


def test_legacy_null_sources_reads_as_empty():
    # A row written before the column existed reads back NULL → [].
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE functions (address TEXT, sources TEXT)")
    conn.execute("INSERT INTO functions (address, sources) VALUES ('0x1', NULL)")
    row = conn.execute("SELECT sources FROM functions").fetchone()
    assert decode_sources(row[0]) == []
