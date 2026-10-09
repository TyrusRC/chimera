"""MCP tool schemas: sibling tools wrapped natively — mantis (SAST) + centurion (mobile)."""

from __future__ import annotations

from mcp.types import Tool


def tools() -> list[Tool]:
    return [
        Tool(name="mantis_audit",
             description="Run the mantis SAST auditor over a source or decompiled tree — the RE->SAST bridge for chimera: point it at recovered source (jadx/apktool output, Ghidra/Hex-Rays C, a carved frontend) to statically find vulns. mantis runs OpenGrep plus a multi-engine layer (bandit/gosec/njsscan/eslint-security/checkov + trivy/grype) that is ON by default when the engines are installed, and returns finding dicts (rule_id, severity, path, lines, message, verdict). SAST-only by default (no LLM/provider needed); `llm=true` adds mantis's LLM triage. `decompiled=true` (default) detects the stack from source extensions when there's no build file — the usual chimera case. `packs`/`mode` pick rule packs; `engines` narrows or disables the layer (csv of engine names, 'auto'/'all', or 'none'); `engines_offline` skips the network SCA engines (trivy/grype). Needs the mantis-sast package (pip install mantis-sast).",
             inputSchema={"type": "object", "properties": {
                 "path": {"type": "string", "description": "Source or decompiled tree to audit."},
                 "mode": {"type": "string", "description": "mantis mode/rule-pack selector (quick|deep|secrets|iac|mobile|web|...); mutually exclusive with packs."},
                 "packs": {"type": "array", "items": {"type": "string"}, "description": "Explicit rule packs (e.g. [\"mobile-android\",\"secrets\"]); bypasses mode + inventory."},
                 "engines": {"type": "string", "description": "SAST engine selection (default on): a csv (bandit,gosec,njsscan,eslint-security,checkov,trivy,grype), 'auto', 'all', or 'none' for OpenGrep-only."},
                 "engines_offline": {"type": "boolean", "default": False, "description": "Skip the network SCA engines (trivy/grype) so the run stays fully offline."},
                 "decompiled": {"type": "boolean", "default": True, "description": "Detect the stack from source extensions alone (no build files) — the chimera case."},
                 "llm": {"type": "boolean", "default": False, "description": "Also run mantis's LLM triage (needs a configured provider)."},
             }, "required": ["path"]}),

        Tool(name="centurion_tools",
             description="List the centurion mobile QA + pentest toolkit's wrapped tools and whether each is installed — makes centurion's toolbox visible to the agent inside chimera. centurion wraps the OWASP MASTG tool set (Android/iOS: adb, jadx, apktool, apksigner, apkid, apkleaks, frida, objection, class-dump, otool, ldid, ...) + generic (opengrep, gitleaks, radare2, mitmproxy). Returns each tool's name, platform, category, installed status, version, and install hint for the missing ones — so the agent can plan a mobile engagement. Needs the centurion package (pip install centurion).",
             inputSchema={"type": "object", "properties": {}}),
    ]
