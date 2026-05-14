"""Build a single self-contained report from an analyzed model + cache.

Produces a `dict` payload that callers can serialize to JSON, and a
`render_html` helper that turns the same payload into a one-file HTML
view an analyst can open in a browser. The payload is the source of
truth — HTML is a presentation layer over it.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from chimera.core.cache import AnalysisCache
from chimera.detection_engineering.masvs import build_masvs_matrix
from chimera.model.program import UnifiedProgramModel


def _behavior_section(sha: str, cache, native_protection: dict, protection_profile: dict) -> dict:
    """Aggregate anti-analysis / network / persistence / IOC / packer signals."""
    aa_evidence: list[str] = []
    for k in ("anti_debug_evidence", "anti_vm_evidence", "self_inject_evidence"):
        v = (native_protection or {}).get(k) or []
        if isinstance(v, list):
            aa_evidence.extend(str(x) for x in v)

    anti_analysis = {
        "anti_debug": bool((native_protection or {}).get("has_anti_debug")) or bool((protection_profile or {}).get("anti_debug")),
        "anti_vm": bool((native_protection or {}).get("has_anti_vm")) or bool((protection_profile or {}).get("anti_emulator")),
        "anti_frida": bool((protection_profile or {}).get("anti_frida")),
        "root_jailbreak_detect": bool((protection_profile or {}).get("root_detect")) or bool((protection_profile or {}).get("jailbreak_detect")),
        "self_inject": bool((native_protection or {}).get("has_self_inject")),
        "evidence": aa_evidence[:50],
    }

    persistence_extra = cache.get_json(sha, "elf_persistence") or []
    persistence = {
        "indicators_present": bool((native_protection or {}).get("has_persistence_strings")) or bool(persistence_extra),
        "elf_persistence_count": len(persistence_extra) if isinstance(persistence_extra, list) else 0,
    }

    network = {
        "cleartext_permitted": bool((protection_profile or {}).get("cleartext_traffic")),
        "user_ca_trusted": bool((protection_profile or {}).get("user_ca_trusted")),
        "pinning_present": bool((protection_profile or {}).get("pinning_present")),
    }

    iocs = cache.get_json(sha, "iocs") or {}
    packer = {
        "detected": bool((native_protection or {}).get("packer_detected")),
        "name": (native_protection or {}).get("packer_name"),
    }

    return {
        "anti_analysis": anti_analysis,
        "network": network,
        "persistence": persistence,
        "iocs": iocs,
        "packer": packer,
    }


def _attack_surface_section(model: UnifiedProgramModel, sha: str, cache) -> dict:
    """Format-appropriate entry points an attacker could reach."""
    out: dict = {"format": model.binary.format.value}

    if model.imports:
        by_bucket: dict[str, list[str]] = {}
        for imp in model.imports:
            key = f"{imp.dll}!{imp.name}" if imp.dll else (imp.name or "?")
            by_bucket.setdefault(imp.bucket or "other", []).append(key)
        out["imports_by_bucket"] = {k: sorted(set(v))[:200] for k, v in by_bucket.items()}

    components = cache.get_json(sha, "manifest_components") or []
    if components:
        out["exported_components"] = [
            {"kind": c.get("kind"), "name": c.get("name"), "has_intent_filter": c.get("has_intent_filter", False)}
            for c in components
            if c.get("exported")
        ]

    url_schemes = cache.get_json(sha, "url_schemes") or []
    if url_schemes:
        out["url_schemes"] = list(url_schemes)[:100]

    return out


def build_report(model: UnifiedProgramModel, cache: AnalysisCache) -> dict:
    """Aggregate model + cache state into one analyst-ready report payload."""
    sha = model.binary.sha256
    triage = cache.get_json(sha, "triage") or {}
    jadx_meta = cache.get_json(sha, "jadx") or {}
    manifest_bytes = cache.get(sha, "manifest_xml")
    native_protections = cache.get_json(sha, "native_protections") or {}
    native_protection = cache.get_json(sha, "native_protection") or {}
    protection_profile = cache.get_json(sha, "protection_profile") or {}

    # Per-native-lib backend results — walk the cache dir.
    sha_dir = cache.cache_dir / sha[:2] / sha
    libs: dict[str, dict[str, Any]] = {}
    if sha_dir.exists():
        for entry in sorted(sha_dir.iterdir()):
            for prefix in ("r2_", "ghidra_"):
                if entry.name.startswith(prefix):
                    lib = entry.name[len(prefix):]
                    tag = prefix.rstrip("_")
                    try:
                        blob = json.loads(entry.read_text())
                    except (OSError, json.JSONDecodeError):
                        continue
                    libs.setdefault(lib, {})[tag] = _summarize_lib_blob(tag, blob)

    cross_layer_bindings: list[dict] = []
    for f in model.functions:
        if f.layer != "jvm":
            continue
        if not f.metadata or not f.metadata.get("is_native"):
            continue
        callees = model.get_callees(f.address)
        if callees:
            for c in callees:
                edge_type = "jni-static"
                for e in model._call_edges:
                    if e.caller_addr == f.address and e.callee_addr == c.address:
                        edge_type = e.call_type
                        break
                cross_layer_bindings.append({
                    "jvm": f.address, "native": c.address, "type": edge_type,
                })
        else:
            cross_layer_bindings.append({
                "jvm": f.address, "native": None, "type": "unbound",
            })

    # Collect ilspy_ keys for .NET assemblies. Read each key once.
    ilspy_payloads = [
        p
        for k in cache.list_keys(sha)
        if k.startswith("ilspy_")
        for p in (cache.get_json(sha, k),)
        if p
    ]

    return {
        "schema": "chimera-report/1",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "binary": {
            "sha256": sha,
            "path": str(model.binary.path),
            "format": model.binary.format.value,
            "platform": model.binary.platform.value,
            "arch": model.binary.arch.value,
            "framework": model.binary.framework.value,
            "size_bytes": model.binary.size_bytes,
            "package_name": model.binary.package_name,
            "version": model.binary.version,
        },
        "triage": triage,
        "jadx": {
            "decompiled_files": jadx_meta.get("decompiled_files", 0),
            "package_count": len(jadx_meta.get("packages", []) or []),
            "packages": jadx_meta.get("packages", []),
            "sources_dir": jadx_meta.get("sources_dir"),
        },
        "native_libraries": libs,
        "model": {
            "function_count": len(model.functions),
            "string_count": len(model.get_strings()),
            "functions": [
                {
                    "address": f.address,
                    "name": f.name,
                    "original_name": f.original_name,
                    "language": f.language,
                    "layer": f.layer,
                    "classification": f.classification,
                    "source_backend": f.source_backend,
                }
                for f in list(model.functions)[:1000]
            ],
            "strings": [
                {"address": s.address, "value": s.value, "section": s.section}
                for s in list(model.get_strings())[:1000]
            ],
            "function_truncated": len(model.functions) > 1000,
            "string_truncated": len(model.get_strings()) > 1000,
        },
        "manifest_present": manifest_bytes is not None,
        "native_protections": native_protections,
        "cross_layer": {"bindings": cross_layer_bindings},
        "pe_header": cache.get_json(sha, "pe_header") or {},
        "pe_imports": cache.get_json(sha, "pe_imports") or {},
        "pe_flags": cache.get_json(sha, "pe_flags") or {},
        "elf_persistence": cache.get_json(sha, "elf_persistence") or [],
        "elf_syscalls": cache.get_json(sha, "elf_syscalls") or {},
        "dotnet_assemblies": ilspy_payloads,
        "native_protection": native_protection,
        "behavior": _behavior_section(sha, cache, native_protection, protection_profile),
        "attack_surface": _attack_surface_section(model, sha, cache),
        "masvs": build_masvs_matrix(model, cache),
        "imports": [
            {"dll": e.dll, "name": e.name, "address": e.address, "ordinal": e.ordinal, "bucket": e.bucket}
            for e in model.imports
        ][:500],
        "vol_pslist":            cache.get_json(sha, "vol_pslist") or {},
        "vol_pstree":            cache.get_json(sha, "vol_pstree") or {},
        "vol_bash":              cache.get_json(sha, "vol_bash") or {},
        "vol_netstat":           cache.get_json(sha, "vol_netstat") or {},
        "vol_malfind":           cache.get_json(sha, "vol_malfind") or {},
        "vol_lsmod":             cache.get_json(sha, "vol_lsmod") or {},
        "vol_check_modules":     cache.get_json(sha, "vol_check_modules") or {},
        "vol_check_syscall":     cache.get_json(sha, "vol_check_syscall") or {},
        "memory_persistence":    cache.get_json(sha, "memory_persistence") or {},
        "memory_protection":     cache.get_json(sha, "memory_protection") or {},
    }


def _render_native_protections_html(nprot: dict) -> str:
    """Render the native_protections payload as readable HTML, not raw JSON.

    Skips the section gracefully when nothing was detected so the report
    doesn't show a confusing empty `{}` block.
    """
    crypto = nprot.get("crypto_algorithms") or []
    packer = nprot.get("commercial_packer")
    obf = nprot.get("obfuscation_techniques") or []
    capabilities = nprot.get("capabilities") or []

    if not (crypto or packer or obf or capabilities):
        return '<p class="meta">No native protections detected on this binary.</p>'

    rows: list[str] = []
    if packer:
        rows.append(f'<tr><th>Commercial packer</th><td><strong>'
                    f'{html.escape(packer)}</strong></td></tr>')
    if crypto:
        chips = " ".join(f'<span class="chip">{html.escape(a)}</span>'
                         for a in crypto)
        rows.append(f"<tr><th>Crypto algorithms</th><td>{chips}</td></tr>")
    if obf:
        chips = " ".join(f'<span class="chip">{html.escape(t)}</span>'
                         for t in obf)
        rows.append(f"<tr><th>Obfuscation</th><td>{chips}</td></tr>")
    table = f'<table class="kv">{"".join(rows)}</table>' if rows else ""

    cap_html = ""
    if capabilities:
        cap_rows = "".join(
            f"<tr><td>{html.escape(c.get('lib') or '')}</td>"
            f"<td>{html.escape(c.get('namespace') or '')}</td>"
            f"<td>{html.escape(c.get('rule') or '')}</td>"
            f"<td>{c.get('address_count', 0)}</td></tr>"
            for c in capabilities[:100]
        )
        more = len(capabilities) - 100
        more_row = (f"<tr><td colspan=4><em>+{more} more</em></td></tr>"
                    if more > 0 else "")
        cap_html = (
            "<h3>Capabilities (capa)</h3>"
            "<table><tr><th>Library</th><th>Namespace</th><th>Rule</th>"
            f"<th>Hits</th></tr>{cap_rows}{more_row}</table>"
        )

    return table + cap_html


def _summarize_lib_blob(tag: str, blob: dict) -> dict:
    if tag == "r2":
        return {
            "function_count": len(blob.get("functions") or []),
            "string_count": len(blob.get("strings") or []),
            "arch": (blob.get("info") or {}).get("arch"),
            "bits": (blob.get("info") or {}).get("bits"),
            "stripped": (blob.get("info") or {}).get("stripped"),
        }
    if tag == "ghidra":
        rc = blob.get("return_code")
        return {
            "return_code": rc,
            "ok": rc == 0,
            "error_first_line": (blob.get("error") or "").splitlines()[0:1] or None,
        }
    return {}


def _render_behavior_html(b: dict) -> str:
    if not b:
        return ""
    aa = b.get("anti_analysis") or {}
    flag_rows = "".join(
        f"<tr><td>{html.escape(k)}</td><td>{'✓' if v else '·'}</td></tr>"
        for k, v in aa.items() if k != "evidence" and isinstance(v, bool)
    )
    evidence = aa.get("evidence") or []
    ev_html = ""
    if evidence:
        items = "".join(f"<li><code>{html.escape(str(e))}</code></li>" for e in evidence[:20])
        ev_html = f"<details><summary>Evidence ({len(evidence)})</summary><ul>{items}</ul></details>"

    net = b.get("network") or {}
    net_rows = "".join(
        f"<tr><td>{html.escape(k)}</td><td>{'✓' if v else '·'}</td></tr>"
        for k, v in net.items() if isinstance(v, bool)
    )

    persistence = b.get("persistence") or {}
    pers_html = (
        f"<tr><td>indicators_present</td><td>{'✓' if persistence.get('indicators_present') else '·'}</td></tr>"
        f"<tr><td>elf_persistence_count</td><td>{int(persistence.get('elf_persistence_count') or 0)}</td></tr>"
    )

    packer = b.get("packer") or {}
    packer_html = ""
    if packer.get("detected") or packer.get("name"):
        packer_html = (
            f"<p>Packer: <strong>{html.escape(str(packer.get('name') or 'detected'))}</strong></p>"
        )

    iocs = b.get("iocs") or {}
    ioc_html = ""
    if isinstance(iocs, dict) and iocs:
        rows = "".join(
            f"<tr><td>{html.escape(cat)}</td><td>{len(vals) if isinstance(vals, list) else '?'}</td>"
            f"<td>{html.escape(', '.join(map(str, (vals or [])[:5])))}</td></tr>"
            for cat, vals in iocs.items()
        )
        ioc_html = (
            "<h3>IOCs</h3><table><tr><th>Category</th><th>Count</th>"
            f"<th>Sample</th></tr>{rows}</table>"
        )

    return (
        "<h2>Behavior</h2>"
        f"<h3>Anti-analysis</h3><table class='kv'>{flag_rows or '<tr><td><em>no flags</em></td><td></td></tr>'}</table>"
        f"{ev_html}"
        f"<h3>Network</h3><table class='kv'>{net_rows or '<tr><td><em>no signals</em></td><td></td></tr>'}</table>"
        f"<h3>Persistence</h3><table class='kv'>{pers_html}</table>"
        f"{packer_html}{ioc_html}"
    )


def _render_attack_surface_html(s: dict) -> str:
    if not s:
        return ""
    parts = [f"<h2>Attack Surface ({html.escape(s.get('format', '?'))})</h2>"]

    comps = s.get("exported_components") or []
    if comps:
        rows = "".join(
            f"<tr><td>{html.escape(c.get('kind') or '?')}</td>"
            f"<td><code>{html.escape(c.get('name') or '?')}</code></td>"
            f"<td>{'✓' if c.get('has_intent_filter') else '·'}</td></tr>"
            for c in comps
        )
        parts.append(
            "<h3>Exported components</h3>"
            f"<table><tr><th>Kind</th><th>Name</th><th>Intent-filter</th></tr>{rows}</table>"
        )

    by_bucket = s.get("imports_by_bucket") or {}
    if by_bucket:
        parts.append("<h3>Imports by bucket</h3>")
        for bucket, names in sorted(by_bucket.items()):
            items = "".join(f"<li><code>{html.escape(str(n))}</code></li>" for n in names[:30])
            parts.append(
                f"<details><summary>{html.escape(bucket)} ({len(names)})</summary>"
                f"<ul>{items}</ul></details>"
            )

    schemes = s.get("url_schemes") or []
    if schemes:
        chips = "".join(f"<span class='chip'>{html.escape(str(u))}</span>" for u in schemes)
        parts.append(f"<h3>URL schemes</h3><p>{chips}</p>")

    return "".join(parts)


def _render_masvs_html(matrix: dict) -> str:
    if not matrix or not matrix.get("applicable"):
        return ""
    rows = matrix.get("rows") or []
    if not rows:
        return ""
    body = "".join(
        f"<tr><td><code>{html.escape(r.get('control_id') or '')}</code></td>"
        f"<td>{html.escape(r.get('name') or '')}</td>"
        f"<td>{html.escape(r.get('status') or '')}</td>"
        f"<td>{html.escape(r.get('notes') or '')}</td></tr>"
        for r in rows
    )
    return (
        "<h2>MASVS Matrix</h2>"
        "<table><tr><th>Control</th><th>Name</th><th>Status</th><th>Notes</th></tr>"
        f"{body}</table>"
    )


def render_html(report: dict) -> str:
    """Render the report dict as a single self-contained HTML page."""
    binary = report["binary"]
    jadx = report["jadx"]
    triage = report["triage"]
    libs = report["native_libraries"]
    model = report["model"]
    title = f"Chimera report — {Path(binary['path']).name}"

    libs_rows = "".join(
        f"<tr><td>{html.escape(lib)}</td>"
        f"<td>{html.escape(json.dumps(parts.get('r2', {})))}</td>"
        f"<td>{html.escape(json.dumps(parts.get('ghidra', {})))}</td></tr>"
        for lib, parts in libs.items()
    ) or "<tr><td colspan=3><em>none analyzed</em></td></tr>"

    fn_rows = "".join(
        f"<tr><td><code>{html.escape(f['address'])}</code></td>"
        f"<td>{html.escape(f['name'])}</td>"
        f"<td>{html.escape(f.get('layer') or '')}</td>"
        f"<td>{html.escape(f.get('language') or '')}</td>"
        f"<td>{html.escape(f.get('source_backend') or '')}</td></tr>"
        for f in model["functions"][:200]
    ) or "<tr><td colspan=5><em>model has no functions — see report.md gap notes</em></td></tr>"

    str_rows = "".join(
        f"<tr><td><code>{html.escape(s['address'])}</code></td>"
        f"<td>{html.escape(s.get('section') or '')}</td>"
        f"<td><code>{html.escape(s['value'][:120])}</code></td></tr>"
        for s in model["strings"][:200]
    ) or "<tr><td colspan=3><em>none</em></td></tr>"

    pkg_list = "".join(f"<li>{html.escape(p)}</li>" for p in jadx["packages"][:200])
    if jadx["package_count"] > 200:
        pkg_list += f"<li><em>… +{jadx['package_count'] - 200} more</em></li>"

    nprot = report.get("native_protections") or {}
    nprot_html = _render_native_protections_html(nprot)
    behavior_html = _render_behavior_html(report.get("behavior") or {})
    attack_surface_html = _render_attack_surface_html(report.get("attack_surface") or {})
    masvs_html = _render_masvs_html(report.get("masvs") or {})

    cl_bindings = (report.get("cross_layer") or {}).get("bindings") or []
    cl_rows = "".join(
        f"<tr><td><code>{html.escape(b['jvm'])}</code></td>"
        f"<td><code>{html.escape(b['native'] or '—')}</code></td>"
        f"<td>{html.escape(b['type'])}</td></tr>"
        for b in cl_bindings
    ) or "<tr><td colspan=3><em>none</em></td></tr>"

    # PE imports buckets table
    pe_imports = report.get("pe_imports") or {}
    pe_imports_rows = "".join(
        f"<tr><td>{html.escape(b)}</td>"
        f"<td>{info.get('score', 0)}</td>"
        f"<td>{info.get('weight', 0):.1f}</td>"
        f"<td><code>{html.escape(', '.join(info.get('imports', [])[:8]))}</code></td></tr>"
        for b, info in pe_imports.items()
    ) or "<tr><td colspan=4><em>none</em></td></tr>"

    # ELF persistence findings table
    elf_persistence = report.get("elf_persistence") or []
    persistence_rows = "".join(
        f"<tr><td>{html.escape(r.get('category', ''))}</td>"
        f"<td><code>{html.escape(r.get('path', ''))}</code></td>"
        f"<td><code>{html.escape((r.get('evidence') or '')[:120])}</code></td>"
        f"<td>{html.escape(r.get('string_address') or '—')}</td></tr>"
        for r in elf_persistence
    ) or "<tr><td colspan=4><em>none</em></td></tr>"

    # .NET assemblies (one outer table per assembly, types listed)
    dotnet_blob = report.get("dotnet_assemblies") or []
    dotnet_html_parts: list[str] = []
    for asm in dotnet_blob:
        asm_name = asm.get("assembly", "?")
        types = asm.get("types") or []
        type_rows = "".join(
            f"<tr><td>{html.escape(t.get('namespace', ''))}</td>"
            f"<td>{html.escape(t.get('name', ''))}</td>"
            f"<td>{t.get('size_bytes', 0):,}</td></tr>"
            for t in types[:200]
        ) or "<tr><td colspan=3><em>no types</em></td></tr>"
        dotnet_html_parts.append(
            f"<h3>{html.escape(asm_name)} — {len(types)} type(s)</h3>"
            f"<table><tr><th>Namespace</th><th>Type</th><th>Size</th></tr>{type_rows}</table>"
        )
    dotnet_html = "\n".join(dotnet_html_parts) or '<p class="meta">No managed assemblies decompiled.</p>'

    # Native protection summary (PE/ELF profile)
    native_prot = report.get("native_protection") or {}
    np_rows: list[str] = []
    if native_prot.get("packer"):
        np_rows.append(f"<tr><th>Packer</th><td><strong>{html.escape(native_prot['packer'])}</strong></td></tr>")
    np_rows.append(f"<tr><th>Anti-debug</th><td>{'yes' if native_prot.get('has_anti_debug') else 'no'}</td></tr>")
    np_rows.append(f"<tr><th>Anti-VM</th><td>{'yes' if native_prot.get('has_anti_vm') else 'no'}</td></tr>")
    np_rows.append(f"<tr><th>Self-injection</th><td>{'yes' if native_prot.get('has_self_inject') else 'no'}</td></tr>")
    np_rows.append(f"<tr><th>Persistence strings</th><td>{'yes' if native_prot.get('has_persistence_strings') else 'no'}</td></tr>")
    np_rows.append(f"<tr><th>High-entropy sections</th><td>{native_prot.get('high_entropy_section_count', 0)}</td></tr>")
    native_prot_html = (
        f'<table class="kv">{"".join(np_rows)}</table>'
        if any(native_prot.values()) else
        '<p class="meta">No native-side protection signals detected.</p>'
    )

    # Memory analysis sections
    vol_pslist = report.get("vol_pslist") or {}
    pslist_rows_data = vol_pslist.get("rows") or []
    process_count = len(pslist_rows_data)

    vol_pstree = report.get("vol_pstree") or {}
    pstree_text = vol_pstree.get("text") or ""
    if not pstree_text and vol_pstree.get("rows"):
        # Render a simple indent-tree from rows if text field absent
        pstree_text = "\n".join(
            f"{'  ' * int(r.get('depth', 0))}{r.get('pid', '?')} {r.get('name', '?')}"
            for r in (vol_pstree.get("rows") or [])
        )
    pstree_html = html.escape(pstree_text) if pstree_text else "<em>no process tree data</em>"

    vol_bash = report.get("vol_bash") or {}
    bash_count = len(vol_bash.get("rows") or [])

    vol_netstat = report.get("vol_netstat") or {}
    netstat_count = len(vol_netstat.get("rows") or [])

    vol_malfind = report.get("vol_malfind") or {}
    malfind_count = len(vol_malfind.get("rows") or [])

    vol_lsmod = report.get("vol_lsmod") or {}
    lsmod_count = len(vol_lsmod.get("rows") or [])

    vol_check_modules = report.get("vol_check_modules") or {}
    hidden_module_count = len(vol_check_modules.get("rows") or [])

    vol_check_syscall = report.get("vol_check_syscall") or {}
    hooked_syscall_count = len([
        r for r in (vol_check_syscall.get("rows") or [])
        if r.get("handler_symbol") in (None, "", "UNKNOWN")
    ])

    mem_pers = report.get("memory_persistence") or {}
    mem_pers_findings = mem_pers.get("findings") or []
    mem_persistence_rows = "".join(
        f"<tr><td>{html.escape(r.get('category', ''))}</td>"
        f"<td><code>{html.escape(r.get('path', ''))}</code></td>"
        f"<td>{html.escape(str(r.get('inode', '—')))}</td></tr>"
        for r in mem_pers_findings
    ) or "<tr><td colspan=3><em>none</em></td></tr>"

    # Gate memory sections — only include block when image is a memory image
    has_memory_data = any([
        process_count, bash_count, netstat_count, malfind_count,
        lsmod_count, hidden_module_count, hooked_syscall_count, mem_pers_findings,
    ])
    memory_sections_html = ""
    if has_memory_data:
        memory_sections_html = f"""
<h2>Memory analysis — process tree ({process_count} processes)</h2>
<details><summary>process tree</summary>
<pre>{pstree_html}</pre>
</details>

<h2>Memory artifacts</h2>
<table>
  <tr><th>Bash commands</th><td>{bash_count}</td></tr>
  <tr><th>Network connections</th><td>{netstat_count}</td></tr>
  <tr><th>Malfind hits</th><td>{malfind_count}</td></tr>
  <tr><th>Kernel modules</th><td>{lsmod_count}</td></tr>
  <tr><th>Hidden modules</th><td>{hidden_module_count}</td></tr>
  <tr><th>Hooked syscalls</th><td>{hooked_syscall_count}</td></tr>
</table>

<h2>Memory persistence</h2>
<table>
<tr><th>Category</th><th>Path</th><th>Inode</th></tr>
{mem_persistence_rows}
</table>
"""

    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<title>{html.escape(title)}</title>
<style>
body {{ font: 14px/1.4 -apple-system, system-ui, sans-serif; margin: 24px; color: #222; }}
h1, h2 {{ border-bottom: 1px solid #ddd; padding-bottom: 4px; }}
h1 {{ font-size: 22px; }} h2 {{ font-size: 17px; margin-top: 28px; }}
table {{ border-collapse: collapse; width: 100%; margin: 8px 0 16px; }}
th, td {{ text-align: left; padding: 4px 8px; border-bottom: 1px solid #eee; vertical-align: top; }}
th {{ background: #f6f6f6; font-weight: 600; }}
code {{ font: 12px ui-monospace, Menlo, monospace; background: #f3f3f3; padding: 0 4px; border-radius: 3px; }}
.meta {{ color: #666; font-size: 12px; }}
ul.compact {{ columns: 3; column-gap: 24px; font-size: 12px; }}
.chip {{ display: inline-block; padding: 1px 8px; margin: 2px;
        border-radius: 10px; background: #eef3ff; color: #1e3a8a;
        font-size: 12px; }}
table.kv th {{ width: 200px; }}
</style></head>
<body>
<h1>{html.escape(title)}</h1>
<p class="meta">Generated {html.escape(report['generated_at'])} · schema {html.escape(report['schema'])}</p>

<h2>Binary</h2>
<table>
<tr><th>SHA256</th><td><code>{html.escape(binary['sha256'])}</code></td></tr>
<tr><th>Format</th><td>{html.escape(binary['format'])}</td></tr>
<tr><th>Platform</th><td>{html.escape(binary['platform'])}</td></tr>
<tr><th>Arch</th><td>{html.escape(binary['arch'])}</td></tr>
<tr><th>Framework</th><td>{html.escape(binary['framework'])}</td></tr>
<tr><th>Size</th><td>{binary['size_bytes']:,} bytes</td></tr>
<tr><th>Package</th><td>{html.escape(binary.get('package_name') or '—')}</td></tr>
<tr><th>Version</th><td>{html.escape(binary.get('version') or '—')}</td></tr>
</table>

{behavior_html}

{attack_surface_html}

{masvs_html}

<h2>Triage</h2>
<pre><code>{html.escape(json.dumps(triage, indent=2))}</code></pre>

<h2>jadx — {jadx['decompiled_files']:,} files, {jadx['package_count']:,} packages</h2>
<ul class="compact">{pkg_list}</ul>

<h2>Native libraries</h2>
<table>
<tr><th>Library</th><th>r2 summary</th><th>ghidra summary</th></tr>
{libs_rows}
</table>

<h2>Native protections</h2>
{nprot_html}

<h2>Cross-layer bindings</h2>
<table>
  <tr><th>JVM method</th><th>Native fn</th><th>Type</th></tr>
  {cl_rows}
</table>

<h2>PE imports</h2>
<table>
<tr><th>Bucket</th><th>Score</th><th>Weight</th><th>Sample imports</th></tr>
{pe_imports_rows}
</table>

<h2>ELF persistence</h2>
<table>
<tr><th>Category</th><th>Path</th><th>Evidence</th><th>Address</th></tr>
{persistence_rows}
</table>

<h2>.NET assemblies</h2>
{dotnet_html}

<h2>Native protection profile</h2>
{native_prot_html}
{memory_sections_html}
<h2>Model — {model['function_count']:,} functions / {model['string_count']:,} strings</h2>
<h3>Functions (first 200)</h3>
<table><tr><th>Address</th><th>Name</th><th>Layer</th><th>Language</th><th>Backend</th></tr>{fn_rows}</table>
<h3>Strings (first 200)</h3>
<table><tr><th>Address</th><th>Section</th><th>Value</th></tr>{str_rows}</table>

</body></html>
"""
