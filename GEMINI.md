# Chimera — agent guide

Chimera is a reverse-engineering MCP server. Its tools appear as
`mcp__chimera__<tool>` (e.g. `mcp__chimera__status`, `mcp__chimera__analyze`).

Start with `status`, then `analyze(path=...)`, then load the workflow via
`list_skills` + `get_skill("re-workflow")`. Recon (paged `get_functions` /
`get_strings` / `detect_*`) before decompiling; reach for a solving primitive
(`symexec`, `emulate_function`, `find_dispatch_tables`, `recover_cfg`, `patch`)
before hand-scripting; persist findings with the write-back tools. Run untrusted
targets confined (`run_sandboxed`); Docker is the isolation env, not the default
runtime.
