# Chimera on DeepSeek Harness (dsh)

dsh bridges MCP through its built-in `@deepseek-ai/dsh-mcp-client` plugin, and
discovers on-disk skills through `@deepseek-ai/dsh-skill-filesystem`. So chimera
plugs in with **config only** — no custom plugin.

## Fastest path

```sh
chimera install            # auto-detects ~/.dsh and writes the rows below
```

Or add them by hand to `~/.dsh/cordis.patch.yml` (see
[`deepseek-harness-cordis.yml`](deepseek-harness-cordis.yml)).

## What you get

- **Tools:** chimera's MCP tools appear as `mcp__chimera__<tool>` (e.g.
  `mcp__chimera__status`, `mcp__chimera__analyze`).
- **Skills:** the `.claude/skills` tree is registered as a `customSkillDirs`
  root, so chimera's skills show up in the dsh skill catalog. dsh bridges MCP
  *tools only*, so the same skills are also reachable via the
  `mcp__chimera__list_skills` / `mcp__chimera__get_skill` tools on any host.

## Verify

1. Start dsh: `npx @deepseek-ai/dsh web`.
2. Saving the patch hot-reloads (no restart). Confirm a call to
   `mcp__chimera__status` returns, and `mcp__chimera__list_skills` lists the
   catalog (including `re-workflow`).
