"""`chimera db` command group.

Handles database provisioning and status checks. Uses synchronous psycopg
because click callbacks are sync — keeps this command group independent
of the asyncio runtime used by the main analysis path.
"""

from __future__ import annotations

import sys
from urllib.parse import urlparse, urlunparse

import click
import psycopg
from psycopg import sql as pgsql

from chimera.model.schema import PROJECT_SCHEMA


def _admin_dsn(dsn: str) -> str:
    """Return a DSN pointing at the maintenance `postgres` database.

    Creating the target DB requires connecting somewhere else first.
    """
    parsed = urlparse(dsn)
    return urlunparse(parsed._replace(path="/postgres"))


def _target_dbname(dsn: str) -> str:
    path = urlparse(dsn).path
    return path.lstrip("/") or "postgres"


@click.group(name="db")
def db_cli() -> None:
    """Database provisioning and migration commands."""


@db_cli.command("init")
@click.option("--dsn", envvar="CHIMERA_DB_URL", required=True,
              help="Postgres DSN for the project database.")
def init_cmd(dsn: str) -> None:
    """Create the project database (if missing), install extensions, apply schema."""
    admin = _admin_dsn(dsn)
    target = _target_dbname(dsn)

    try:
        # Step 1: ensure the target DB exists.
        with psycopg.connect(admin, autocommit=True) as conn:
            existing = conn.execute(
                "SELECT 1 FROM pg_database WHERE datname = %s", (target,)
            ).fetchone()
            if existing is None:
                conn.execute(
                    pgsql.SQL("CREATE DATABASE {}").format(pgsql.Identifier(target))
                )
                click.echo(f"Created database {target!r}")
            else:
                click.echo(f"Database {target!r} already exists")

        # Step 2: install extensions + apply schema in the target DB.
        with psycopg.connect(dsn, autocommit=True) as conn:
            conn.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm;")
            conn.execute("CREATE EXTENSION IF NOT EXISTS btree_gin;")
            conn.execute(PROJECT_SCHEMA)
    except (psycopg.OperationalError, psycopg.ProgrammingError) as exc:
        click.echo(f"Init failed: {exc}", err=True)
        sys.exit(1)

    click.echo("Extensions + schema applied.")


@db_cli.command("status")
@click.option("--dsn", envvar="CHIMERA_DB_URL", required=True)
def status_cmd(dsn: str) -> None:
    """Report connectivity, server version, and table count."""
    try:
        with psycopg.connect(dsn) as conn:
            version = conn.execute("SELECT version();").fetchone()[0]
            tables = conn.execute(
                "SELECT count(*) FROM pg_catalog.pg_tables "
                "WHERE schemaname = 'public'"
            ).fetchone()[0]
    except psycopg.OperationalError as exc:
        click.echo(f"Cannot connect: {exc}", err=True)
        sys.exit(1)
    click.echo(f"Connected: {version.split(',')[0]}")
    click.echo(f"Public tables: {tables}")
