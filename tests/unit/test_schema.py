"""Smoke tests for schema DDL strings."""

from chimera.model.schema import PROJECT_SCHEMA, PROJECT_TABLES


def test_schema_declares_all_expected_tables():
    assert set(PROJECT_TABLES) == {
        "binaries", "functions", "call_graph", "strings",
        "permissions", "protections", "sdks",
    }


def test_schema_uses_postgres_types():
    # Heuristic: no SQLite-isms should leak through.
    lowered = PROJECT_SCHEMA.lower()
    assert "bigserial" in lowered, "functions PK should use BIGSERIAL"
    assert "timestamptz" in lowered, "timestamp columns should use TIMESTAMPTZ"
    assert "autoincrement" not in lowered, "AUTOINCREMENT is SQLite-only"


def test_schema_uses_trigram_index_on_name():
    assert "gin_trgm_ops" in PROJECT_SCHEMA, "expected trigram index for regex predicates"
