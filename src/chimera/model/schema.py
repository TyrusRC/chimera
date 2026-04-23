"""DDL for the chimera_projects database.

These are the tables migrated from the SQLite era. New IR/enrichment
tables are added in subsequent plan steps.
"""

from __future__ import annotations

PROJECT_TABLES: tuple[str, ...] = (
    "binaries",
    "functions",
    "call_graph",
    "strings",
    "permissions",
    "protections",
    "sdks",
)

PROJECT_SCHEMA: str = """
CREATE TABLE IF NOT EXISTS binaries (
    sha256 TEXT PRIMARY KEY,
    path TEXT NOT NULL,
    format TEXT NOT NULL,
    platform TEXT NOT NULL,
    arch TEXT NOT NULL,
    framework TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    package_name TEXT,
    version TEXT,
    min_sdk INTEGER,
    analyzed_at TIMESTAMPTZ DEFAULT NOW(),
    analysis_version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS functions (
    id BIGSERIAL PRIMARY KEY,
    binary_sha256 TEXT NOT NULL REFERENCES binaries(sha256) ON DELETE CASCADE,
    address TEXT NOT NULL,
    name TEXT NOT NULL,
    original_name TEXT NOT NULL,
    language TEXT NOT NULL,
    classification TEXT NOT NULL,
    layer TEXT NOT NULL,
    source_backend TEXT NOT NULL,
    decompiled TEXT,
    signature TEXT,
    ai_renamed BOOLEAN DEFAULT FALSE,
    ai_comments TEXT,
    UNIQUE (binary_sha256, address)
);

CREATE INDEX IF NOT EXISTS functions_name_trgm_idx
    ON functions USING gin (name gin_trgm_ops);

CREATE TABLE IF NOT EXISTS call_graph (
    caller_binary TEXT NOT NULL REFERENCES binaries(sha256) ON DELETE CASCADE,
    caller_addr TEXT NOT NULL,
    callee_addr TEXT NOT NULL,
    call_type TEXT NOT NULL DEFAULT 'direct',
    PRIMARY KEY (caller_binary, caller_addr, callee_addr)
);

CREATE INDEX IF NOT EXISTS idx_callgraph_callee
    ON call_graph(caller_binary, callee_addr);

CREATE TABLE IF NOT EXISTS strings (
    id BIGSERIAL PRIMARY KEY,
    binary_sha256 TEXT NOT NULL REFERENCES binaries(sha256) ON DELETE CASCADE,
    address TEXT NOT NULL,
    value TEXT NOT NULL,
    section TEXT,
    decrypted_from TEXT
);

CREATE INDEX IF NOT EXISTS strings_value_trgm_idx
    ON strings USING gin (value gin_trgm_ops);

CREATE TABLE IF NOT EXISTS permissions (
    binary_sha256 TEXT NOT NULL REFERENCES binaries(sha256) ON DELETE CASCADE,
    permission TEXT NOT NULL,
    declared BOOLEAN DEFAULT TRUE,
    actually_used BOOLEAN DEFAULT FALSE,
    PRIMARY KEY (binary_sha256, permission)
);

CREATE TABLE IF NOT EXISTS protections (
    id BIGSERIAL PRIMARY KEY,
    binary_sha256 TEXT NOT NULL REFERENCES binaries(sha256) ON DELETE CASCADE,
    type TEXT NOT NULL,
    product TEXT,
    bypassed BOOLEAN DEFAULT FALSE,
    bypass_method TEXT
);

CREATE TABLE IF NOT EXISTS sdks (
    id BIGSERIAL PRIMARY KEY,
    binary_sha256 TEXT NOT NULL REFERENCES binaries(sha256) ON DELETE CASCADE,
    name TEXT NOT NULL,
    version TEXT,
    package_prefix TEXT,
    risk_level TEXT DEFAULT 'clean',
    known_cves TEXT
);
"""
