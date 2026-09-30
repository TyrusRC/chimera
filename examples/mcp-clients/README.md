# MCP client configs

Ready-to-paste config per agent host. The launch command is the same
everywhere (chimera's stdio MCP server); only each host's file and key differ.
`chimera install` writes these live and auto-detected — these files are for
manual setup or reference.

| Host | This file | Goes in | Key |
|---|---|---|---|
| Claude Code | `claude-code.mcp.json` | `.mcp.json` (project) · `~/.claude.json` (user) | `mcpServers` |
| Claude Desktop | `claude-code.mcp.json` | `claude_desktop_config.json` | `mcpServers` |
| OpenAI Codex CLI | `codex-config.toml` | `~/.codex/config.toml` | `[mcp_servers.chimera]` |
| Gemini CLI | `gemini-settings.json` | `~/.gemini/settings.json` | `mcpServers` |
| Google Antigravity | `antigravity-mcp_config.json` | `~/.gemini/config/mcp_config.json` | `mcpServers` |
| Cursor | `cursor.mcp.json` | `.cursor/mcp.json` · `~/.cursor/mcp.json` | `mcpServers` |
| Windsurf | `windsurf-mcp_config.json` | `~/.codeium/windsurf/mcp_config.json` | `mcpServers` |
| VS Code (Copilot) | `vscode.mcp.json` | `.vscode/mcp.json` | `servers` |
| DeepSeek Harness (dsh) | `deepseek-harness-cordis.yml` | `~/.dsh/cordis.patch.yml` | plugin row → `mcp__chimera__*` |

The no-clone launch command uses `uvx`; for a local checkout, swap
`command`/`args` for `<repo>/.venv/bin/chimera` `["mcp"]`. See
[`deepseek-harness.md`](deepseek-harness.md) for the dsh walkthrough.
