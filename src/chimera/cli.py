"""Chimera CLI — command-line interface for mobile reverse engineering."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import click

from chimera import __version__
from chimera.cli_db import db_cli


@click.group()
@click.version_option(version=__version__, prog_name="chimera")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose output")
def main(verbose: bool):
    """Chimera — Mobile reverse engineering platform. Many backends, one beast."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


main.add_command(db_cli)


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--project-dir", type=click.Path(), default=None, help="Project directory")
@click.option("--cache-dir", type=click.Path(), default=None, help="Cache directory")
@click.option("--device", type=str, default=None, help="ADB device or iOS UDID")
@click.option("--ghidra-home", type=str, default=None, help="Ghidra install path")
@click.option("--mapping-file", type=click.Path(exists=True), default=None,
              help="ProGuard/R8 mapping.txt to restore original identifiers")
def analyze(path: str, project_dir: str | None, cache_dir: str | None,
            device: str | None, ghidra_home: str | None,
            mapping_file: str | None):
    """Analyze a mobile app binary (APK, IPA, DEX, Mach-O, ELF .so)."""
    asyncio.run(_analyze(path, project_dir, cache_dir, device, ghidra_home, mapping_file))


async def _analyze(path: str, project_dir: str | None, cache_dir: str | None,
                   device: str | None, ghidra_home: str | None,
                   mapping_file: str | None):
    from chimera.core.config import ChimeraConfig
    from chimera.core.engine import ChimeraEngine

    config = ChimeraConfig(
        project_dir=Path(project_dir) if project_dir else Path.cwd() / "chimera_project",
        cache_dir=Path(cache_dir) if cache_dir else Path.cwd() / "chimera_cache",
        ghidra_home=ghidra_home,
        adb_device=device,
        mapping_file=Path(mapping_file) if mapping_file else None,
    )
    engine = ChimeraEngine(config)
    try:
        click.echo(f"Chimera v{__version__} — analyzing {Path(path).name}")
        click.echo()
        model = await engine.analyze(path)
        click.echo("Analysis complete:")
        click.echo(f"  Platform:  {model.binary.platform.value}")
        click.echo(f"  Format:    {model.binary.format.value}")
        click.echo(f"  Framework: {_framework_label(model)}")
        click.echo(f"  SHA256:    {model.binary.sha256[:16]}...")
        click.echo(f"  Functions: {len(model.functions)}")
        click.echo(f"  Strings:   {len(model.get_strings())}")

        # Per-native-lib outcomes from the cache so the analyst can see
        # which library each backend actually analyzed (not just "ghidra
        # ran"). Walks the cache for r2_<name>/ghidra_<name> entries.
        from chimera.core.cache import AnalysisCache
        cache = AnalysisCache(config.cache_dir)
        per_lib = _per_native_lib_summary(cache, model.binary.sha256)
        if per_lib:
            click.echo()
            click.echo("  Native libraries analyzed:")
            for lib, info in per_lib.items():
                click.echo(f"    {lib}: {info}")

        native_protections = cache.get_json(model.binary.sha256, "native_protections") or {}
        flags: list[str] = []
        if native_protections.get("commercial_packer"):
            flags.append(f"packer={native_protections['commercial_packer']}")
        if native_protections.get("crypto_algorithms"):
            flags.append(f"crypto={','.join(native_protections['crypto_algorithms'])}")
        if native_protections.get("obfuscation_techniques"):
            flags.append(f"obf={','.join(native_protections['obfuscation_techniques'])}")
        if native_protections.get("capabilities"):
            flags.append(f"capa={len(native_protections['capabilities'])} hits")
        if flags:
            click.echo()
            click.echo("  Native protections:   " + " · ".join(flags))

        click.echo()
        available = [a.name() for a in engine.registry.all_available()]
        unavailable = [a.name() for a in engine.registry.all_registered() if not a.is_available()]
        click.echo(f"  Backends used:        {', '.join(available) or 'none'}")
        if unavailable:
            click.echo(f"  Backends unavailable: {', '.join(unavailable)}")
    finally:
        await engine.cleanup()


def _framework_label(model) -> str:
    """Honest framework label for the analyze summary.

    `Framework.NONE` becomes "none (jvm/kotlin)" on Android and
    "none (objc/swift)" on iOS so the analyst sees what code layer they're
    actually looking at, not just an enum value that reads as "C/C++".
    """
    fw = model.binary.framework.value
    plat = model.binary.platform.value
    if fw == "none":
        if plat == "android":
            return "none (jvm/kotlin)"
        if plat == "ios":
            return "none (objc/swift)"
    return fw


def _per_native_lib_summary(cache, sha256: str) -> dict[str, str]:
    """Summarize per-lib backend outcomes by walking cache keys.

    Looks for `r2_<lib>` and `ghidra_<lib>` blobs and reports lib name →
    one-line status (function count / error). Empty dict if no native
    libs were analyzed.
    """
    libs: dict[str, dict[str, str]] = {}
    sha_dir = cache.cache_dir / sha256[:2] / sha256
    if not sha_dir.exists():
        return {}
    import json as _json
    for entry in sha_dir.iterdir():
        name = entry.name
        for prefix in ("r2_", "ghidra_"):
            if name.startswith(prefix):
                lib = name[len(prefix):]
                tag = prefix.rstrip("_")
                try:
                    blob = _json.loads(entry.read_text())
                except (OSError, _json.JSONDecodeError):
                    continue
                libs.setdefault(lib, {})[tag] = _summarize_backend_blob(tag, blob)
    return {lib: ", ".join(f"{tag}={summary}" for tag, summary in sorted(parts.items()))
            for lib, parts in sorted(libs.items())}


def _summarize_backend_blob(tag: str, blob: dict) -> str:
    if tag == "r2":
        return f"{len(blob.get('functions') or [])} fn / {len(blob.get('strings') or [])} str"
    if tag == "ghidra":
        rc = blob.get("return_code")
        if rc != 0:
            err = (blob.get("error") or "").splitlines()[0:1]
            return f"failed (rc={rc}{'; ' + err[0] if err else ''})"
        funcs = blob.get("functions") or blob.get("ExportFunctions") or []
        n = len(funcs) if isinstance(funcs, list) else 0
        return f"{n} fn"
    return "ok"


@main.command()
def info():
    """Show Chimera version and available backends."""
    from chimera.adapters.ghidra import GhidraAdapter
    from chimera.adapters.jadx import JadxAdapter
    from chimera.adapters.radare2 import Radare2Adapter

    click.echo(f"Chimera v{__version__}")
    click.echo()
    click.echo("Backend status:")
    for adapter_cls in [Radare2Adapter, GhidraAdapter, JadxAdapter]:
        adapter = adapter_cls()
        status = "available" if adapter.is_available() else "NOT FOUND"
        click.echo(f"  {adapter.name():12} {status}")


@main.command()
@click.option("--platform", "plat", type=click.Choice(["android", "ios"]), default=None,
              help="Filter by platform")
def devices(plat: str | None):
    """List connected devices."""
    asyncio.run(_devices(plat))


async def _devices(plat: str | None):
    from chimera.device.android import AndroidDeviceManager
    from chimera.device.ios import IOSDeviceManager

    managers = []
    if plat in (None, "android"):
        managers.append(AndroidDeviceManager())
    if plat in (None, "ios"):
        managers.append(IOSDeviceManager())

    found = False
    for mgr in managers:
        if not mgr.is_available:
            click.echo(f"  {mgr.name}: tool not installed")
            continue
        dev_list = await mgr.list_devices()
        for d in dev_list:
            found = True
            root_status = ""
            if d.is_rooted:
                root_status = " [rooted]"
            elif d.is_jailbroken:
                root_status = " [jailbroken]"
            click.echo(
                f"  {d.platform.value}: {d.id} — {d.model or '?'} "
                f"({d.os_version or '?'}){root_status}"
            )
        await mgr.cleanup()

    if not found:
        click.echo("  No devices found")


@main.command("detect-protections")
@click.argument("path", type=click.Path(exists=True))
@click.option("--project-dir", type=click.Path(), default=None)
@click.option("--cache-dir", type=click.Path(), default=None)
@click.option("--ghidra-home", type=str, default=None)
def detect_protections(path: str, project_dir: str | None,
                       cache_dir: str | None, ghidra_home: str | None):
    """Detect security protections in a mobile app binary."""
    asyncio.run(_detect_protections(path, project_dir, cache_dir, ghidra_home))


async def _detect_protections(path: str, project_dir: str | None,
                              cache_dir: str | None, ghidra_home: str | None):
    from chimera.core.cache import AnalysisCache
    from chimera.core.config import ChimeraConfig
    from chimera.core.engine import ChimeraEngine
    from chimera.bypass.detector import ProtectionDetector
    from chimera.bypass.jadx_scanner import scan_jadx_tree

    config = ChimeraConfig(
        project_dir=Path(project_dir) if project_dir else Path.cwd() / "chimera_project",
        cache_dir=Path(cache_dir) if cache_dir else Path.cwd() / "chimera_cache",
        ghidra_home=ghidra_home,
    )
    engine = ChimeraEngine(config)
    try:
        model = await engine.analyze(path)
        strings = [s.value for s in model.get_strings()]

        detector = ProtectionDetector()
        profile = detector.detect_from_strings(strings, model.binary.platform.value)

        # Augment with jadx-tree scan so the analyst gets file:line evidence
        # for each detected protection — not just yes/no booleans.
        cache = AnalysisCache(config.cache_dir)
        native_protections = cache.get_json(model.binary.sha256, "native_protections") or {}
        if native_protections.get("commercial_packer"):
            profile.commercial_packer = native_protections["commercial_packer"]
            profile.has_packer = True
            profile.packer_name = profile.packer_name or native_protections["commercial_packer"]
        if native_protections.get("crypto_algorithms"):
            profile.crypto_algorithms = list(native_protections["crypto_algorithms"])
        if native_protections.get("obfuscation_techniques"):
            profile.obfuscation_techniques = list(native_protections["obfuscation_techniques"])
        if native_protections.get("capabilities"):
            profile.capabilities = [
                f"{c.get('namespace')}/{c.get('rule')}".lstrip("/")
                for c in native_protections["capabilities"]
            ]

        jadx_meta = cache.get_json(model.binary.sha256, "jadx") or {}
        sources_dir = jadx_meta.get("sources_dir")
        hits_by_cat: dict[str, list] = {}
        if sources_dir and Path(sources_dir).exists():
            hits = scan_jadx_tree(Path(sources_dir), model.binary.platform.value)
            for h in hits:
                hits_by_cat.setdefault(h.category, []).append(h)
            # Promote any jadx hits into the profile so the booleans match.
            if hits_by_cat.get("root_detection"):
                profile.has_root_detection = True
            if hits_by_cat.get("jailbreak_detection"):
                profile.has_jailbreak_detection = True
            if hits_by_cat.get("anti_frida"):
                profile.has_anti_frida = True
            if hits_by_cat.get("anti_debug"):
                profile.has_anti_debug = True
            if hits_by_cat.get("ssl_pinning"):
                profile.has_ssl_pinning = True
            if hits_by_cat.get("integrity"):
                profile.has_integrity_check = True

        click.echo(f"Protection profile for {Path(path).name}:")
        _emit_protection_line("Root detection:     ", profile.has_root_detection,
                              hits_by_cat.get("root_detection"))
        _emit_protection_line("Jailbreak detection:", profile.has_jailbreak_detection,
                              hits_by_cat.get("jailbreak_detection"))
        _emit_protection_line("Anti-Frida:         ", profile.has_anti_frida,
                              hits_by_cat.get("anti_frida"))
        _emit_protection_line("Anti-debug:         ", profile.has_anti_debug,
                              hits_by_cat.get("anti_debug"))
        _emit_protection_line("SSL pinning:        ", profile.has_ssl_pinning,
                              hits_by_cat.get("ssl_pinning"))
        _emit_protection_line("Integrity checks:   ", profile.has_integrity_check,
                              hits_by_cat.get("integrity"))
        click.echo(f"  Packer:              {'YES (' + (profile.packer_name or '?') + ')' if profile.has_packer else 'no'}")
        if profile.commercial_packer:
            click.echo(f"  Commercial packer:   {profile.commercial_packer}")
        if profile.crypto_algorithms:
            click.echo(f"  Crypto detected:     {', '.join(profile.crypto_algorithms)}")
        if profile.obfuscation_techniques:
            click.echo(f"  Obfuscation:         {', '.join(profile.obfuscation_techniques)}")
        if profile.capabilities:
            top = profile.capabilities[:8]
            more = len(profile.capabilities) - len(top)
            click.echo(f"  Capabilities (capa): {', '.join(top)}"
                       + (f"  (+{more} more)" if more > 0 else ""))
        if profile.has_any_protection:
            click.echo(f"\n  Bypass order: {' -> '.join(profile.bypass_order())}")
    finally:
        await engine.cleanup()


def _emit_protection_line(label: str, present: bool, hits: list | None) -> None:
    """Print one protection row with up to 3 file:line evidence pointers."""
    status = "YES" if present else "no"
    click.echo(f"  {label} {status}")
    if not present or not hits:
        return
    for h in hits[:3]:
        click.echo(f"      ↳ {h.file}:{h.line}  [{h.pattern}]")
    if len(hits) > 3:
        click.echo(f"      ↳ ... +{len(hits) - 3} more")


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--project-dir", type=click.Path(), default=None)
@click.option("--cache-dir", type=click.Path(), default=None)
@click.option("--ghidra-home", type=str, default=None)
def sdks(path: str, project_dir: str | None, cache_dir: str | None,
         ghidra_home: str | None):
    """Detect third-party SDKs in a mobile app."""
    asyncio.run(_sdks(path, project_dir, cache_dir, ghidra_home))


async def _sdks(path: str, project_dir: str | None, cache_dir: str | None,
                ghidra_home: str | None):
    from chimera.core.cache import AnalysisCache
    from chimera.core.config import ChimeraConfig
    from chimera.core.engine import ChimeraEngine
    from chimera.sdk.analyzer import SDKAnalyzer

    config = ChimeraConfig(
        project_dir=Path(project_dir) if project_dir else Path.cwd() / "chimera_project",
        cache_dir=Path(cache_dir) if cache_dir else Path.cwd() / "chimera_cache",
        ghidra_home=ghidra_home,
    )
    engine = ChimeraEngine(config)
    try:
        model = await engine.analyze(path)

        # Prefer jadx-decompiled package list (already package-shaped) over
        # deriving from model.functions, which on Android often only holds
        # native funcs and won't surface JVM SDKs at all.
        packages: set[str] = set()
        cache = AnalysisCache(config.cache_dir)
        jadx_meta = cache.get_json(model.binary.sha256, "jadx") or {}
        for pkg in jadx_meta.get("packages", []) or []:
            if isinstance(pkg, str) and pkg:
                packages.add(pkg)
        # Fall back to model-derived packages for iOS / native-only inputs.
        for func in model.functions:
            if "." in func.name:
                packages.add(func.name.rsplit(".", 1)[0])

        analyzer = SDKAnalyzer()
        detected = analyzer.detect_from_packages(list(packages))
        summary = analyzer.summarize(detected)

        click.echo(f"SDKs detected in {Path(path).name}:")
        click.echo(f"  Total: {summary['total']}")
        for cat, names in summary["categories"].items():
            click.echo(f"  {cat}: {', '.join(names)}")
        if summary["suspicious"]:
            click.echo(f"\n  SUSPICIOUS: {', '.join(s['name'] for s in summary['suspicious'])}")
    finally:
        await engine.cleanup()


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--project-dir", type=click.Path(), default=None)
@click.option("--cache-dir", type=click.Path(), default=None)
@click.option("--ghidra-home", type=str, default=None)
@click.option("--out", "out_path", type=click.Path(), default=None,
              help="Output path. Defaults to <name>.report.{json,html}")
@click.option("--format", "fmt", type=click.Choice(["json", "html", "both"]),
              default="both", help="Output format(s)")
def report(path: str, project_dir: str | None, cache_dir: str | None,
           ghidra_home: str | None, out_path: str | None, fmt: str):
    """Run analysis and write a JSON/HTML report for the analyst."""
    asyncio.run(_report(path, project_dir, cache_dir, ghidra_home, out_path, fmt))


async def _report(path: str, project_dir: str | None, cache_dir: str | None,
                  ghidra_home: str | None, out_path: str | None, fmt: str):
    import json as _json
    from chimera.core.cache import AnalysisCache
    from chimera.core.config import ChimeraConfig
    from chimera.core.engine import ChimeraEngine
    from chimera.report import build_report, render_html

    config = ChimeraConfig(
        project_dir=Path(project_dir) if project_dir else Path.cwd() / "chimera_project",
        cache_dir=Path(cache_dir) if cache_dir else Path.cwd() / "chimera_cache",
        ghidra_home=ghidra_home,
    )
    engine = ChimeraEngine(config)
    try:
        model = await engine.analyze(path)
        cache = AnalysisCache(config.cache_dir)
        payload = build_report(model, cache)

        base = Path(out_path) if out_path else Path.cwd() / f"{Path(path).stem}.report"
        wrote: list[str] = []
        if fmt in ("json", "both"):
            json_path = base.with_suffix(".json")
            json_path.write_text(_json.dumps(payload, indent=2))
            wrote.append(str(json_path))
        if fmt in ("html", "both"):
            html_path = base.with_suffix(".html")
            html_path.write_text(render_html(payload))
            wrote.append(str(html_path))

        click.echo(f"Report written for {Path(path).name}:")
        for p in wrote:
            click.echo(f"  {p}")
    finally:
        await engine.cleanup()


@main.command()
@click.option("--host", default="0.0.0.0", help="Bind host")
@click.option("--port", default=8080, help="Bind port")
def serve(host: str, port: int):
    """Start the Chimera web UI server."""
    import uvicorn
    click.echo(f"Chimera v{__version__} — starting web UI on http://{host}:{port}")
    uvicorn.run("chimera.api.server:app", host=host, port=port, reload=False)


@main.command()
@click.option("--cache-dir", type=click.Path(), default=None,
              help="Cache root to browse (default: ./chimera_cache)")
def tui(cache_dir: str | None):
    """Launch the Chimera TUI — browse analysis results and devices."""
    from chimera.tui.app import run_tui
    run_tui(Path(cache_dir) if cache_dir else None)


@main.command()
def mcp():
    """Start the Chimera MCP server (for Claude Code / LLM integration)."""
    from chimera.mcp_server import main as mcp_main
    click.echo("Starting Chimera MCP server...")
    asyncio.run(mcp_main())


if __name__ == "__main__":
    main()
