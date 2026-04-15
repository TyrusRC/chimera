"""Chimera CLI — command-line interface for mobile reverse engineering."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import click

from chimera import __version__


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


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--project-dir", type=click.Path(), default=None, help="Project directory")
@click.option("--cache-dir", type=click.Path(), default=None, help="Cache directory")
@click.option("--device", type=str, default=None, help="ADB device or iOS UDID")
@click.option("--ghidra-home", type=str, default=None, help="Ghidra install path")
def analyze(path: str, project_dir: str | None, cache_dir: str | None,
            device: str | None, ghidra_home: str | None):
    """Analyze a mobile app binary (APK, IPA, DEX, Mach-O, ELF .so)."""
    asyncio.run(_analyze(path, project_dir, cache_dir, device, ghidra_home))


async def _analyze(path: str, project_dir: str | None, cache_dir: str | None,
                   device: str | None, ghidra_home: str | None):
    from chimera.core.config import ChimeraConfig
    from chimera.core.engine import ChimeraEngine

    config = ChimeraConfig(
        project_dir=Path(project_dir) if project_dir else Path.cwd() / "chimera_project",
        cache_dir=Path(cache_dir) if cache_dir else Path.cwd() / "chimera_cache",
        ghidra_home=ghidra_home,
        adb_device=device,
    )
    engine = ChimeraEngine(config)
    try:
        click.echo(f"Chimera v{__version__} — analyzing {Path(path).name}")
        click.echo()
        model = await engine.analyze(path)
        click.echo("Analysis complete:")
        click.echo(f"  Platform:  {model.binary.platform.value}")
        click.echo(f"  Format:    {model.binary.format.value}")
        click.echo(f"  SHA256:    {model.binary.sha256[:16]}...")
        click.echo(f"  Functions: {len(model.functions)}")
        click.echo(f"  Strings:   {len(model.get_strings())}")
        click.echo()

        findings = getattr(model, "findings", [])
        if findings:
            from chimera.vuln.finding import Severity
            crit = sum(1 for f in findings if f.severity == Severity.CRITICAL)
            high = sum(1 for f in findings if f.severity == Severity.HIGH)
            med = sum(1 for f in findings if f.severity == Severity.MEDIUM)
            low = sum(1 for f in findings if f.severity == Severity.LOW)
            click.echo(f"  Findings:  {len(findings)} total ({crit} critical, {high} high, {med} medium, {low} low)")
        else:
            click.echo("  Findings:  0")
        click.echo()

        available = [a.name() for a in engine.registry.all_available()]
        unavailable = [a.name() for a in engine.registry.all_registered() if not a.is_available()]
        click.echo(f"  Backends used:        {', '.join(available) or 'none'}")
        if unavailable:
            click.echo(f"  Backends unavailable: {', '.join(unavailable)}")
    finally:
        await engine.cleanup()


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
@click.argument("input_path", type=click.Path(exists=True))
@click.option("--format", "fmt", type=click.Choice(["sarif", "json", "markdown"]), default="sarif",
              help="Report format")
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Output file (default: stdout)")
@click.option("--project-dir", type=click.Path(), default=None)
@click.option("--cache-dir", type=click.Path(), default=None)
@click.option("--ghidra-home", type=str, default=None)
def report(input_path: str, fmt: str, output: str | None,
           project_dir: str | None, cache_dir: str | None, ghidra_home: str | None):
    """Generate a security report from analyzing a mobile app binary."""
    asyncio.run(_report(input_path, fmt, output, project_dir, cache_dir, ghidra_home))


async def _report(input_path: str, fmt: str, output: str | None,
                  project_dir: str | None, cache_dir: str | None, ghidra_home: str | None):
    from chimera.core.config import ChimeraConfig
    from chimera.core.engine import ChimeraEngine
    from chimera.report.sarif import generate_sarif
    from chimera.report.json_report import generate_json
    from chimera.report.markdown import generate_markdown

    config = ChimeraConfig(
        project_dir=Path(project_dir) if project_dir else Path.cwd() / "chimera_project",
        cache_dir=Path(cache_dir) if cache_dir else Path.cwd() / "chimera_cache",
        ghidra_home=ghidra_home,
    )
    engine = ChimeraEngine(config)
    try:
        model = await engine.analyze(input_path)
        findings = getattr(model, "findings", [])

        binary_info = {
            "name": Path(input_path).name,
            "sha256": model.binary.sha256,
            "platform": model.binary.platform.value,
            "format": model.binary.format.value,
        }

        if fmt == "sarif":
            content = generate_sarif(findings)
        elif fmt == "json":
            content = generate_json(findings, binary_info)
        else:
            content = generate_markdown(findings, binary_info)

        if output:
            Path(output).write_text(content)
            click.echo(f"Report written to {output}")
        else:
            click.echo(content)
    finally:
        await engine.cleanup()


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
    from chimera.core.config import ChimeraConfig
    from chimera.core.engine import ChimeraEngine
    from chimera.bypass.detector import ProtectionDetector

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

        click.echo(f"Protection profile for {Path(path).name}:")
        click.echo(f"  Root detection:      {'YES' if profile.has_root_detection else 'no'}")
        click.echo(f"  Jailbreak detection: {'YES' if profile.has_jailbreak_detection else 'no'}")
        click.echo(f"  Anti-Frida:          {'YES' if profile.has_anti_frida else 'no'}")
        click.echo(f"  Anti-debug:          {'YES' if profile.has_anti_debug else 'no'}")
        click.echo(f"  SSL pinning:         {'YES' if profile.has_ssl_pinning else 'no'}")
        click.echo(f"  Integrity checks:    {'YES' if profile.has_integrity_check else 'no'}")
        click.echo(f"  Packer:              {'YES (' + (profile.packer_name or '?') + ')' if profile.has_packer else 'no'}")
        if profile.has_any_protection:
            click.echo(f"\n  Bypass order: {' -> '.join(profile.bypass_order())}")
    finally:
        await engine.cleanup()


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

        packages = set()
        for func in model.functions:
            if "." in func.name:
                parts = func.name.rsplit(".", 1)
                packages.add(parts[0])

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
@click.option("--host", default="0.0.0.0", help="Bind host")
@click.option("--port", default=8080, help="Bind port")
def serve(host: str, port: int):
    """Start the Chimera web UI server."""
    import uvicorn
    click.echo(f"Chimera v{__version__} — starting web UI on http://{host}:{port}")
    uvicorn.run("chimera.api.server:app", host=host, port=port, reload=False)


@main.command()
def tui():
    """Launch the Chimera TUI for device interaction."""
    from chimera.tui.app import run_tui
    run_tui()


@main.command()
def mcp():
    """Start the Chimera MCP server (for Claude Code / LLM integration)."""
    from chimera.mcp_server import main as mcp_main
    click.echo("Starting Chimera MCP server...")
    asyncio.run(mcp_main())


if __name__ == "__main__":
    main()
