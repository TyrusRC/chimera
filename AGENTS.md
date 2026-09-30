# Chimera — agent guide

Chimera is a reverse-engineering MCP server. Its tools appear to you as
`mcp__chimera__<tool>` (e.g. `mcp__chimera__status`, `mcp__chimera__analyze`).

## Start here
1. `status` — what backends are available and whether a binary is loaded.
2. `analyze(path=...)` — run the pipeline on a target (once per binary; the
   session holds it).
3. `list_skills` then `get_skill("re-workflow")` — chimera's RE workflow and the
   cheap→expensive tool order. Load the relevant skill before deep analysis.

## Working rules
- Recon before depth: `get_functions` / `get_strings` (paged) / `detect_*`
  before decompiling. Page large lists with `offset`/`limit`.
- Reach for a solving primitive before hand-scripting (`symexec`, `emulate_function`,
  `find_dispatch_tables`, `recover_cfg`, `patch`, …) — see `get_skill("re-workflow")`.
- Persist findings with the write-back tools (`rename_function`, `set_comment`,
  `add_note`, `batch_annotate`) so they survive across sessions.
- To run an untrusted target, do it confined (`run_sandboxed` / the sandbox skill);
  Docker is the isolation env, not the default runtime.
