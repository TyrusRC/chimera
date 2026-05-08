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
from chimera.model.program import UnifiedProgramModel


def build_report(model: UnifiedProgramModel, cache: AnalysisCache) -> dict:
    """Aggregate model + cache state into one analyst-ready report payload."""
    sha = model.binary.sha256
    triage = cache.get_json(sha, "triage") or {}
    jadx_meta = cache.get_json(sha, "jadx") or {}
    manifest_bytes = cache.get(sha, "manifest_xml")
    native_protections = cache.get_json(sha, "native_protections") or {}

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

    # Collect ilspy_ keys for .NET assemblies
    ilspy_keys = [k for k in cache.list_keys(sha) if k.startswith("ilspy_")]
    ilspy_payloads = [cache.get_json(sha, k) for k in ilspy_keys if cache.get_json(sha, k)]

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
        "native_protection": cache.get_json(sha, "native_protection") or {},
        "imports": [
            {"dll": e.dll, "name": e.name, "address": e.address, "ordinal": e.ordinal, "bucket": e.bucket}
            for e in model.imports
        ][:500],
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

<h2>Model — {model['function_count']:,} functions / {model['string_count']:,} strings</h2>
<h3>Functions (first 200)</h3>
<table><tr><th>Address</th><th>Name</th><th>Layer</th><th>Language</th><th>Backend</th></tr>{fn_rows}</table>
<h3>Strings (first 200)</h3>
<table><tr><th>Address</th><th>Section</th><th>Value</th></tr>{str_rows}</table>

</body></html>
"""
