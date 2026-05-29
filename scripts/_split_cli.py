"""One-shot helper: split chimera/cli.py into a chimera.cli package.

Reads the existing chimera/cli.py, parses it as a Python AST, and writes
per-command modules under chimera/cli/. Each module contains:

  * the command's @main.command / @main.group decorated function
  * any module-level helpers it references (best-effort)
  * a `from chimera.cli._root import main` import

Run from the repo root:
    python scripts/_split_cli.py

The helper is destructive — back up before running (we use git).
"""

from __future__ import annotations

import ast
import textwrap
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "chimera" / "cli.py"
PKG = ROOT / "src" / "chimera" / "_cli_pkg"

# Grouping policy: (module_name, set of command/helper top-level names).
# Items not listed here go into `_misc.py`. Helpers shared across modules
# go into `_common.py`.
GROUPS = {
    "frida_cmd": {"frida", "frida_list", "frida_show", "frida_run", "_frida_run"},
    "analyze": {"analyze", "_analyze", "_framework_label",
                "_per_native_lib_summary", "_summarize_backend_blob"},
    "info": {"info", "_count_yara_rules", "_count_sdk_signatures",
             "_semgrep_rules_dir"},
    "devices_cmd": {"devices", "_devices"},
    "protection": {"detect_protections", "_detect_protections",
                   "_emit_protection_line"},
    "diff_cmd": {"diff", "diff_functions"},
    "manifest_cmd": {"manifest"},
    "sdks_cmd": {"sdks", "_sdks"},
    "report_cmd": {"report", "_report"},
    "serve_cmd": {"serve", "tui", "mcp"},
    "jni_cmd": {"jni", "_jni_cmd"},
    "imports_cmd": {"imports", "_imports_cmd"},
    "persistence_cmd": {"persistence", "_persistence_cmd"},
    "yara_cmd": {"yara", "_yara_cmd"},
    "ioc_cmd": {"ioc", "_ioc_cmd"},
    "memory_cmd": {"memory", "_ensure_path", "memory_pslist", "memory_netstat",
                   "memory_malfind", "memory_findings",
                   "_print_pslist", "_print_netstat", "_print_malfind",
                   "_memory_full", "_memory_section", "_memory_findings"},
    "patch_cmd": {"patch"},
    "gdb_export_cmd": {"gdb_export", "_emit_gdbinit", "_sanitise_gdb_var",
                       "_gdb_export_cmd"},
    "attach_cmd": {"attach", "_attach_cmd"},
    "unpack_cmd": {"unpack"},
    "ai_cmd": {"ai", "_ai_decompile", "_ai_call",
               "ai_explain", "ai_rename", "ai_comment",
               "ai_refine_decomp", "ai_batch_rename", "_parse_rename_json"},
    "varbert_cmd": {"varbert", "varbert_rename"},
    "classify_cmd": {"classify"},
    "flutter_cmd": {"flutter_extract"},
    "overlay_cmd": {"overlay", "overlay_export", "overlay_import"},
}

COMMON_HELPERS = {"_load_cache_and_sha"}


def parse_source() -> tuple[str, ast.Module]:
    source = SRC.read_text()
    return source, ast.parse(source)


def extract_segments(source: str, tree: ast.Module) -> dict[str, tuple[int, str]]:
    """Map top-level node name -> (source_lineno, source_text).

    Segments include leading decorators and any attached comment/blank
    padding so the original section headers move with their command. The
    `source_lineno` is the first-line position used to keep within-file
    ordering when we regroup — Click @group.command decorators must
    execute AFTER the group itself is defined, so source order matters.
    """
    lines = source.splitlines(keepends=True)
    out: dict[str, tuple[int, str]] = {}
    prev_end = 0
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                 ast.ClassDef)):
            prev_end = node.end_lineno or prev_end
            continue
        if getattr(node, "decorator_list", None):
            start_line = min(d.lineno for d in node.decorator_list)
        else:
            start_line = node.lineno
        start_idx = start_line - 1
        end_idx = (node.end_lineno or start_line)
        while start_idx > prev_end:
            prev = lines[start_idx - 1].rstrip()
            if prev == "" or prev.startswith("#"):
                start_idx -= 1
            else:
                break
        segment = "".join(lines[start_idx:end_idx])
        out[node.name] = (start_idx + 1, segment)
        prev_end = end_idx
    return out


def file_header(module_doc: str, *, needs_main: bool, needs_asyncio: bool,
                needs_json: bool, needs_path: bool, needs_click: bool) -> str:
    """Generate a tidy header for a generated cli submodule."""
    lines = [f'"""{module_doc}"""', "", "from __future__ import annotations", ""]
    if needs_asyncio:
        lines.append("import asyncio")
    if needs_json:
        lines.append("import json")
    lines.append("import logging")
    if needs_path:
        lines.append("from pathlib import Path")
    lines.append("")
    if needs_click:
        lines.append("import click")
        lines.append("")
    lines.append("from chimera import __version__")
    if needs_main:
        lines.append("from chimera._cli_pkg._root import main")
    lines.append("")
    lines.append("logger = logging.getLogger(__name__)")
    lines.append("")
    return "\n".join(lines) + "\n"


def write_module(name: str, segments: list[tuple[int, str]], doc: str) -> None:
    # Click decorators run at import time and `@ai.command(...)` needs
    # `ai` (the group) to already exist. Sort by source position so the
    # group definition lands before its subcommands inside each module.
    segments_sorted = [seg for _line, seg in sorted(segments, key=lambda t: t[0])]
    body = "\n\n".join(s.rstrip() for s in segments_sorted) + "\n"
    needs_asyncio = "asyncio." in body or "asyncio.run" in body
    needs_json = "json." in body or "json.load" in body or "json.dumps" in body
    needs_path = "Path(" in body or "Path." in body
    needs_main = "@main." in body or "main.add" in body
    header = file_header(
        doc,
        needs_main=needs_main,
        needs_asyncio=needs_asyncio,
        needs_json=needs_json,
        needs_path=needs_path,
        needs_click=True,
    )
    PKG.mkdir(parents=True, exist_ok=True)
    (PKG / f"{name}.py").write_text(header + body)


def main() -> None:
    source, tree = parse_source()
    segments = extract_segments(source, tree)

    grouped: dict[str, list[tuple[int, str]]] = defaultdict(list)
    assigned: set[str] = set()

    for group_name, members in GROUPS.items():
        for member in members:
            if member in segments:
                grouped[group_name].append(segments[member])
                assigned.add(member)

    # Common helpers
    for name in COMMON_HELPERS:
        if name in segments:
            grouped["_common"].append(segments[name])
            assigned.add(name)

    # Leftover top-level functions/classes go into _misc
    for name, payload in segments.items():
        if name in assigned or name == "main":
            continue
        if name.startswith("__"):
            continue
        grouped["_misc"].append(payload)
        assigned.add(name)

    for group_name, segs in grouped.items():
        doc = f"chimera.cli — {group_name.replace('_', ' ')} commands."
        write_module(group_name, segs, doc)

    # Final report so the human can sanity-check coverage.
    print(f"wrote {len(grouped)} modules to {PKG}")
    for name, segs in sorted(grouped.items()):
        print(f"  {name}.py — {len(segs)} symbols")
    unassigned = [n for n in segments if n not in assigned and n != "main"]
    if unassigned:
        print(f"WARNING: {len(unassigned)} unassigned top-level symbols:")
        for n in unassigned:
            print(f"  {n}")


if __name__ == "__main__":
    main()
