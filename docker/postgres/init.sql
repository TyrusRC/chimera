-- Runs exactly once, on first container start, as superuser.
-- Creates both databases and installs extensions in each.

CREATE DATABASE chimera_projects;
CREATE DATABASE chimera_patterns;

\c chimera_projects
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS btree_gin;
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

\c chimera_patterns
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS btree_gin;
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
