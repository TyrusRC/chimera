"""Tools that read analysis artifacts off disk.

Decompiled sources, cached backend output, disassembly, and the
semgrep pass. `read_cache` is a trust boundary — the category name comes
from the caller, so it goes through the session allowlist.

Returns None when the tool is not one of this module's, so the server can
try the next handler group.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from mcp.types import TextContent

from chimera import mcp_session as mcpstate

logger = logging.getLogger(__name__)


async def dispatch(name: str, arguments: dict) -> list[TextContent] | None:
    engine = mcpstate.get_engine()
    if name == "run_semgrep":
        if not mcpstate.require_model():
            return mcpstate.error("No analysis loaded.")
        semgrep = engine.registry.get("semgrep")
        if not semgrep or not semgrep.is_available():
            return mcpstate.error("Semgrep is not installed. Install via: pip install semgrep")
        sha = mcpstate.current_model.binary.sha256[:12]
        sources_dir = engine.config.project_dir / "jadx" / sha / "sources"
        if not sources_dir.exists():
            return mcpstate.error("No decompiled sources found. Semgrep requires jadx output.")
        rules = arguments.get("rules", "auto")
        result = await semgrep.analyze(str(sources_dir), {"rules": rules})
        findings_count = len(result.get("results", []))
        return mcpstate.json_reply({
            "return_code": result.get("return_code"),
            "findings": findings_count,
            "results": result.get("results", [])[:30],
            "errors": result.get("errors", [])[:10],
        })

    # ── list_devices ────────────────────────────────────────────────────
    if name == "list_source_files":
        if not mcpstate.require_model():
            return mcpstate.error("No analysis loaded.")
        sha = mcpstate.current_model.binary.sha256[:12]
        sources_dir = engine.config.project_dir / "jadx" / sha / "sources"
        if not sources_dir.exists():
            return mcpstate.error("No decompiled sources. jadx must be installed and analysis must have run.")
        rel_path = arguments.get("path", "")
        target = sources_dir / rel_path if rel_path else sources_dir
        try:
            target.resolve().relative_to(sources_dir.resolve())
        except ValueError:
            return mcpstate.error("Path traversal not allowed.")
        if not target.exists():
            return mcpstate.error(f"Path not found: {rel_path}")
        pattern = arguments.get("pattern")
        if pattern:
            files = sorted(target.rglob(pattern))
        elif target.is_dir():
            files = sorted(target.iterdir())
        else:
            files = [target]
        entries = []
        for f in files[:200]:
            rel = f.relative_to(sources_dir)
            entries.append({"path": str(rel), "type": "dir" if f.is_dir() else "file",
                            "size": f.stat().st_size if f.is_file() else None})
        return mcpstate.json_reply({"base": rel_path, "count": len(entries), "entries": entries})

    # ── read_source ─────────────────────────────────────────────────────
    if name == "read_source":
        if not mcpstate.require_model():
            return mcpstate.error("No analysis loaded.")
        sha = mcpstate.current_model.binary.sha256[:12]
        sources_dir = engine.config.project_dir / "jadx" / sha / "sources"
        file_path = sources_dir / arguments["path"]
        # Security: prevent path traversal
        try:
            file_path.resolve().relative_to(sources_dir.resolve())
        except ValueError:
            return mcpstate.error("Path traversal not allowed.")
        if not file_path.exists():
            return mcpstate.error(f"File not found: {arguments['path']}")
        content = file_path.read_text(errors="replace")
        lines = content.splitlines()
        offset = arguments.get("offset", 0)
        limit = arguments.get("limit", 200)
        page = lines[offset:offset + limit]
        return mcpstate.json_reply({
            "path": arguments["path"],
            "total_lines": len(lines),
            "offset": offset,
            "lines": len(page),
            "has_more": offset + limit < len(lines),
            "content": "\n".join(page),
        })

    # ── read_cache ──────────────────────────────────────────────────────
    if name == "read_cache":
        if not mcpstate.require_model():
            return mcpstate.error("No analysis loaded.")
        category = arguments["category"]
        if not mcpstate.is_allowed_category(category):
            return mcpstate.error(
                f"Category '{category}' is not in the allow-list. "
                f"Allowed: {sorted(_ALLOWED_CACHE_CATEGORIES)} + prefixes {list(_ALLOWED_CACHE_PREFIXES)}"
            )
        data = engine.cache.get_json(mcpstate.current_model.binary.sha256, category)
        if data is None:
            return mcpstate.error(f"No cached data for category '{category}'. Use list_artifacts to see available keys.")
        return mcpstate.json_reply({"category": category, "data": data})

    # ── list_artifacts ──────────────────────────────────────────────────
    if name == "list_artifacts":
        if not mcpstate.require_model():
            return mcpstate.error("No analysis loaded.")
        sha = mcpstate.current_model.binary.sha256
        artifacts = {"cache": [], "directories": []}

        # Cache entries
        cache_dir = engine.cache._entry_dir(sha)
        if cache_dir.exists():
            for f in sorted(cache_dir.iterdir()):
                if f.is_file():
                    artifacts["cache"].append({
                        "key": f.name,
                        "size": f.stat().st_size,
                    })

        # On-disk output directories
        sha_short = sha[:12]
        for label, path in [
            ("unpacked", engine.config.project_dir / "unpacked" / sha_short),
            ("jadx_sources", engine.config.project_dir / "jadx" / sha_short / "sources"),
            ("jadx_resources", engine.config.project_dir / "jadx" / sha_short / "resources"),
            ("ghidra", engine.config.project_dir / "ghidra"),
            ("headers", engine.config.project_dir / "headers" / sha_short),
        ]:
            if path.exists():
                file_count = sum(1 for _ in path.rglob("*") if _.is_file())
                artifacts["directories"].append({"name": label, "path": str(path), "files": file_count})

        return mcpstate.json_reply(artifacts)

    # ── get_disassembly ─────────────────────────────────────────────────
    if name == "get_disassembly":
        if not mcpstate.require_model():
            return mcpstate.error("No analysis loaded.")
        func = mcpstate.current_model.get_function(arguments["address"])
        if not func:
            return mcpstate.error(f"Function {arguments['address']} not found.")
        instructions = getattr(func, "disassembly", None) or []
        return mcpstate.json_reply({
            "address": func.address, "name": func.name,
            "instruction_count": len(instructions),
            "instructions": instructions,
        })

    # ── get_class_headers ───────────────────────────────────────────────
    if name == "get_class_headers":
        if not mcpstate.require_model():
            return mcpstate.error("No analysis loaded.")
        sha = mcpstate.current_model.binary.sha256[:12]
        headers_dir = engine.config.project_dir / "headers" / sha
        if not headers_dir.exists():
            return mcpstate.error("No class-dump headers found. iOS analysis with class-dump must have run.")
        target_file = arguments.get("file")
        if target_file:
            header_path = headers_dir / target_file
            try:
                header_path.resolve().relative_to(headers_dir.resolve())
            except ValueError:
                return mcpstate.error("Path traversal not allowed.")
            if not header_path.exists():
                return mcpstate.error(f"Header not found: {target_file}")
            return mcpstate.json_reply({"file": target_file, "content": header_path.read_text(errors="replace")})
        # List all headers
        headers = sorted(headers_dir.glob("*.h"))
        return mcpstate.json_reply({
            "count": len(headers),
            "headers": [{"name": h.name, "size": h.stat().st_size} for h in headers[:200]],
        })

    # ── list_packages ───────────────────────────────────────────────────
    if name == "objc_xref":
        if not mcpstate.require_model():
            return mcpstate.error("No analysis loaded.")
        sel = arguments.get("selector")
        cls = arguments.get("class_name")
        imp = arguments.get("imp_address")
        model = mcpstate.current_model

        if cls and not sel and not imp:
            return mcpstate.error("class_name requires selector or imp_address")

        if imp:
            # Lookup by IMP address.
            method = next(
                (m for m in model.objc_methods if m.imp_address == imp), None,
            )
            methods = [method] if method else []
        elif sel:
            methods = model.find_objc_method(class_name=cls, selector=sel)
        else:
            return mcpstate.error("must provide selector or imp_address")

        matches = []
        for m in methods:
            callers = [
                {
                    "caller_function": cs.caller_function,
                    "call_address": cs.call_address,
                    "resolution": cs.resolution,
                }
                for cs in model.find_objc_callers(m.imp_address)
            ]
            matches.append({
                "class_name": m.class_name,
                "selector": m.selector,
                "imp_address": m.imp_address,
                "is_class_method": m.is_class_method,
                "type_signature": m.type_signature,
                "category": m.category,
                "declared_in_protocol": m.declared_in_protocol,
                "enriched_signature": m.enriched_signature,
                "callers": callers,
            })

        # Determine metadata_complete flag from triage cache if present.
        metadata_complete = True
        try:
            triage = engine.cache.get_json(model.binary.sha256, "triage") or {}
            ctx = triage.get("objc_xref_context") or {}
            metadata_complete = bool(ctx.get("class_dump_enriched"))
        except (AttributeError, OSError, ValueError):
            metadata_complete = False

        return mcpstate.json_reply({
            "matches": matches,
            "total_methods_in_binary": len(model.objc_methods),
            "total_callsites_in_binary": len(model.objc_callsites),
            "metadata_complete": metadata_complete,
        })

    return None
