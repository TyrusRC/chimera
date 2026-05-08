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


@main.group()
def frida():
    """Run bundled Frida agent scripts against a connected device."""


@frida.command("list")
@click.option("--platform", "platform", type=click.Choice(["android", "ios", "all"]),
              default="all", help="Filter by target platform.")
def frida_list(platform: str):
    """List bundled Frida scripts."""
    from chimera.frida_scripts import list_scripts
    scripts = list_scripts()
    if platform != "all":
        scripts = [s for s in scripts
                   if s.platform == platform or s.platform == "both"]
    if not scripts:
        click.echo("(no scripts available)")
        return
    click.echo(f"{'ID':36s}  {'Platform':10s}  {'Risk':6s}  Name")
    click.echo("-" * 80)
    for s in scripts:
        click.echo(f"{s.id:36s}  {s.platform:10s}  {s.risk:6s}  {s.name}")


@frida.command("show")
@click.argument("script_id")
def frida_show(script_id: str):
    """Print a script's metadata + source to stdout."""
    from chimera.frida_scripts import get_script, read_source
    meta = get_script(script_id)
    if meta is None:
        click.echo(f"chimera frida: no script with id '{script_id}'", err=True)
        raise click.exceptions.Exit(1)
    click.echo(f"# {meta.name}")
    click.echo(f"# id: {meta.id}")
    click.echo(f"# platform: {meta.platform}")
    click.echo(f"# risk: {meta.risk}")
    click.echo(f"# requires: {', '.join(meta.requires) or '(none)'}")
    click.echo(f"# description: {meta.description}")
    click.echo()
    click.echo(read_source(script_id) or "")


@frida.command("run")
@click.argument("script_id")
@click.option("--target", required=True,
              help="Target package name (Android) or bundle id (iOS).")
@click.option("--device", "device_id", default=None,
              help="Device id (default: USB device).")
@click.option("--mode", type=click.Choice(["attach", "spawn"]), default="spawn",
              help="Whether to attach to a running process or spawn fresh.")
@click.option("--duration", type=int, default=30,
              help="How many seconds to keep the script attached.")
def frida_run(script_id: str, target: str, device_id: str | None,
              mode: str, duration: int):
    """Load a bundled script onto a connected device.

    Requires `frida` and `frida-server` running on the target device.
    The script's metadata advertises which platform/runtime it expects;
    chimera will refuse to run a mismatched script.
    """
    asyncio.run(_frida_run(script_id, target, device_id, mode, duration))


async def _frida_run(script_id, target, device_id, mode, duration):
    import asyncio as _aio
    from chimera.adapters.frida_adapter import FridaAdapter
    from chimera.frida_scripts import get_script, read_source

    meta = get_script(script_id)
    if meta is None:
        click.echo(f"chimera frida: no script with id '{script_id}'", err=True)
        raise click.exceptions.Exit(1)

    source = read_source(script_id)
    if not source:
        click.echo(f"chimera frida: failed to read script source", err=True)
        raise click.exceptions.Exit(1)

    adapter = FridaAdapter()
    if not adapter.is_available():
        click.echo("chimera frida: frida-python not installed; "
                   "`pip install frida` and ensure frida-server runs on the target",
                   err=True)
        raise click.exceptions.Exit(2)

    click.echo(f"[chimera] loading {meta.id} ({meta.risk}) on {target}")
    if mode == "spawn":
        session = await adapter.spawn(target, device_id=device_id, script_source=source)
    else:
        session = await adapter.attach(target, device_id=device_id)
        if session:
            await session.load_script(source)

    if session is None:
        click.echo("chimera frida: failed to attach/spawn — see logs", err=True)
        raise click.exceptions.Exit(3)

    click.echo(f"[chimera] script loaded; running for {duration}s — Ctrl+C to stop early")
    try:
        await _aio.sleep(duration)
    except KeyboardInterrupt:
        click.echo("\n[chimera] interrupted")
    finally:
        await adapter.cleanup()
        click.echo("[chimera] detached")


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--project-dir", type=click.Path(), default=None, help="Project directory")
@click.option("--cache-dir", type=click.Path(), default=None, help="Cache directory")
@click.option("--device", type=str, default=None, help="ADB device or iOS UDID")
@click.option("--ghidra-home", type=str, default=None, help="Ghidra install path")
@click.option("--mapping-file", type=click.Path(exists=True), default=None,
              help="ProGuard/R8 mapping.txt to restore original identifiers")
@click.option("--no-ghidra", "skip_ghidra", is_flag=True,
              help="Skip the Ghidra decompile phase entirely (faster on big apps)")
@click.option("--no-jvm-methods", "skip_jvm_methods", is_flag=True,
              help="Skip JVM method-level ingestion (faster, smaller model)")
@click.option("--ghidra-max-lib-mb", type=int, default=None,
              help="Skip Ghidra on native libs over this size in MB (default 20)")
@click.option("--ghidra-max-libs", type=int, default=None,
              help="Cap total libs sent to Ghidra (default 8, smallest-first)")
@click.option("--no-floss", "skip_floss", is_flag=True,
              help="Skip FLOSS string deobfuscation (PE/ELF only)")
@click.option("--no-ilspy", "skip_ilspy", is_flag=True,
              help="Skip ILSpy decompile pass on .NET assemblies")
@click.option("--no-pe-imports", "skip_pe_imports", is_flag=True,
              help="Skip PE import-table scoring")
@click.option("--floss-timeout", "floss_timeout", type=int, default=None,
              help="FLOSS timeout in seconds (default: 90)")
def analyze(path: str, project_dir: str | None, cache_dir: str | None,
            device: str | None, ghidra_home: str | None,
            mapping_file: str | None, skip_ghidra: bool, skip_jvm_methods: bool,
            ghidra_max_lib_mb: int | None, ghidra_max_libs: int | None,
            skip_floss: bool, skip_ilspy: bool, skip_pe_imports: bool,
            floss_timeout: int | None):
    """Analyze a mobile app binary (APK, IPA, DEX, Mach-O, ELF .so)."""
    asyncio.run(_analyze(path, project_dir, cache_dir, device, ghidra_home,
                         mapping_file, skip_ghidra, skip_jvm_methods, ghidra_max_lib_mb, ghidra_max_libs,
                         skip_floss, skip_ilspy, skip_pe_imports, floss_timeout))


async def _analyze(path: str, project_dir: str | None, cache_dir: str | None,
                   device: str | None, ghidra_home: str | None,
                   mapping_file: str | None, skip_ghidra: bool = False, skip_jvm_methods: bool = False,
                   ghidra_max_lib_mb: int | None = None,
                   ghidra_max_libs: int | None = None,
                   skip_floss: bool = False, skip_ilspy: bool = False,
                   skip_pe_imports: bool = False, floss_timeout: int | None = None):
    from chimera.core.config import ChimeraConfig
    from chimera.core.engine import ChimeraEngine

    cfg_kwargs: dict = dict(
        project_dir=Path(project_dir) if project_dir else Path.cwd() / "chimera_project",
        cache_dir=Path(cache_dir) if cache_dir else Path.cwd() / "chimera_cache",
        ghidra_home=ghidra_home,
        adb_device=device,
        mapping_file=Path(mapping_file) if mapping_file else None,
        ghidra_skip=skip_ghidra,
        skip_jvm_methods=skip_jvm_methods,
        skip_floss=skip_floss,
        skip_ilspy=skip_ilspy,
        skip_pe_imports=skip_pe_imports,
    )
    if ghidra_max_lib_mb is not None:
        cfg_kwargs["ghidra_max_lib_mb"] = ghidra_max_lib_mb
    if ghidra_max_libs is not None:
        cfg_kwargs["ghidra_max_libs"] = ghidra_max_libs
    if floss_timeout is not None:
        cfg_kwargs["floss_timeout"] = floss_timeout
    config = ChimeraConfig(**cfg_kwargs)
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

        triage = cache.get_json(model.binary.sha256, "triage") or {}
        skipped = triage.get("ghidra_skipped_libs") or []
        if skipped:
            click.echo()
            click.echo(f"  Ghidra skipped {len(skipped)} lib(s):")
            for entry in skipped[:6]:
                click.echo(f"    {entry['lib']}: {entry['reason']}")
            if len(skipped) > 6:
                click.echo(f"    ... +{len(skipped) - 6} more")

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

        jni = cache.get_json(model.binary.sha256, "jni_summary") or {}
        if jni:
            click.echo()
            click.echo(
                f"  JNI bindings: {jni.get('static', 0) + jni.get('dynamic', 0)} "
                f"({jni.get('static', 0)} static, "
                f"{jni.get('dynamic', 0)} dynamic, "
                f"{jni.get('unresolved', 0)} unresolved)"
            )

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
    """Show Chimera version, available backends, and bundled rule counts."""
    from chimera.adapters.capa_adapter import CapaAdapter
    from chimera.adapters.ghidra import GhidraAdapter
    from chimera.adapters.jadx import JadxAdapter
    from chimera.adapters.radare2 import Radare2Adapter
    from chimera.adapters.yara_adapter import YaraAdapter

    click.echo(f"Chimera v{__version__}")
    click.echo()
    click.echo("Backend status:")
    for adapter_cls in [Radare2Adapter, GhidraAdapter, JadxAdapter,
                        YaraAdapter, CapaAdapter]:
        adapter = adapter_cls()
        status = "available" if adapter.is_available() else "NOT FOUND"
        click.echo(f"  {adapter.name():12} {status}")

    # Surface what the rule-driven pieces actually have loaded so analysts
    # can tell at a glance whether the pipeline will detect anything.
    click.echo()
    click.echo("Rules / signatures loaded:")
    yara_count = _count_yara_rules()
    click.echo(f"  YARA rules:           {yara_count}")
    sdk_count = _count_sdk_signatures()
    click.echo(f"  SDK signatures:       {sdk_count}")
    semgrep_dir = _semgrep_rules_dir()
    if semgrep_dir is not None:
        click.echo(f"  Semgrep rules dir:    {semgrep_dir}")


def _count_yara_rules() -> int:
    rules_dir = Path(__file__).resolve().parent / "bypass" / "yara_rules"
    if not rules_dir.exists():
        return 0
    total = 0
    for path in rules_dir.glob("*.yar"):
        try:
            total += sum(
                1 for line in path.read_text().splitlines()
                if line.strip().startswith("rule ")
            )
        except OSError:
            continue
    return total


def _count_sdk_signatures() -> int:
    try:
        from chimera.sdk.signatures import SDK_SIGNATURES
    except ImportError:
        return 0
    return len(SDK_SIGNATURES)


def _semgrep_rules_dir() -> Path | None:
    """Best-effort discovery of a bundled or env-provided Semgrep rule dir."""
    import os
    env = os.environ.get("CHIMERA_SEMGREP_RULES")
    if env and Path(env).exists():
        return Path(env)
    # Some installs bundle rules at /opt/chimera/semgrep_rules.
    bundled = Path("/opt/chimera/semgrep_rules")
    if bundled.exists():
        return bundled
    return None


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


def _load_cache_and_sha(path: str, project_dir: str | None, cache_dir: str | None):
    """Load the cache and resolve the binary's sha256.

    Helper for CLI commands that need to look up cached analyzer outputs
    by sha256 (e.g. ``chimera manifest``). Computes sha256 directly with
    hashlib so we don't have to spin up the full engine just to read a
    blob out of cache.
    """
    import hashlib
    from chimera.core.cache import AnalysisCache
    from chimera.core.config import ChimeraConfig

    config = ChimeraConfig(
        project_dir=Path(project_dir) if project_dir else Path.cwd() / "chimera_project",
        cache_dir=Path(cache_dir) if cache_dir else Path.cwd() / "chimera_cache",
    )
    cache = AnalysisCache(config.cache_dir)
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return cache, h.hexdigest()


@main.command()
@click.argument("a", type=str)
@click.argument("b", type=str)
@click.option("--cache-dir", type=click.Path(), default=None)
@click.option("--format", "fmt",
              type=click.Choice(["md", "json"]), default="md",
              help="Output format")
@click.option("--out", "out_path", type=click.Path(), default=None,
              help="Write output to this file (default: stdout)")
def diff(a: str, b: str, cache_dir: str | None, fmt: str, out_path: str | None):
    """Diff two cached chimera projects.

    A and B can be sha256 hashes or unique sha256 prefixes (>= 8 chars).
    Both projects must already be cached — run `chimera analyze` first.
    """
    import json as _json
    from chimera.core.cache import AnalysisCache
    from chimera.core.config import ChimeraConfig
    from chimera.diff import (
        ProjectNotInCacheError, diff_projects, load_project,
        render_json, render_markdown,
    )

    config = ChimeraConfig(
        project_dir=Path.cwd() / "chimera_project",
        cache_dir=Path(cache_dir) if cache_dir else Path.cwd() / "chimera_cache",
    )
    cache = AnalysisCache(config.cache_dir)

    try:
        snap_a = load_project(a, cache)
        snap_b = load_project(b, cache)
    except ProjectNotInCacheError as e:
        click.echo(f"project not in cache: {e}", err=True)
        raise SystemExit(2)
    except ValueError as e:
        click.echo(str(e), err=True)
        raise SystemExit(2)

    project_diff = diff_projects(snap_a, snap_b)

    if fmt == "json":
        text = _json.dumps(render_json(project_diff), indent=2)
    else:
        text = render_markdown(project_diff)

    if out_path:
        Path(out_path).write_text(text)
        click.echo(f"wrote {out_path}")
    else:
        click.echo(text)


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--project-dir", type=click.Path(), default=None)
@click.option("--cache-dir", type=click.Path(), default=None)
@click.option("--format", "fmt",
              type=click.Choice(["text", "json"]),
              default="text",
              help="Output format")
def manifest(path: str, project_dir: str | None, cache_dir: str | None, fmt: str):
    """Print AndroidManifest + network_security_config findings.

    Requires the project to have been analyzed (chimera analyze <path>) so
    the manifest XML is in cache.
    """
    import json as _json
    import tempfile
    from chimera.parsers.android_manifest import parse_manifest as _pm
    from chimera.parsers.network_security_config import parse_nsc as _pn
    from chimera.detection_engineering.manifest_findings import build_findings_from_models

    cache, sha = _load_cache_and_sha(path, project_dir, cache_dir)
    manifest_bytes = cache.get(sha, "manifest_xml")
    if manifest_bytes is None:
        click.echo("No manifest_xml in cache. Run `chimera analyze` first.", err=True)
        raise SystemExit(2)

    with tempfile.TemporaryDirectory() as td:
        mp = Path(td) / "AndroidManifest.xml"
        mp.write_bytes(manifest_bytes)
        manifest_model = _pm(mp)
        nsc_bytes = cache.get(sha, "nsc_xml")
        nsc_model = None
        if nsc_bytes:
            np = Path(td) / "network_security_config.xml"
            np.write_bytes(nsc_bytes)
            nsc_model = _pn(np)

        findings = build_findings_from_models(manifest_model, nsc=nsc_model)

    if fmt == "json":
        click.echo(_json.dumps([f.to_dict() for f in findings], indent=2))
        return

    if not findings:
        click.echo("No manifest/NSC findings.")
        return
    click.echo(f"{len(findings)} finding(s):")
    for f in findings:
        click.echo(f"  [{f.severity}] {f.finding_id}: {f.title}")
        for ev in f.evidence:
            click.echo(f"    - {ev}")
        if f.recommendation:
            click.echo(f"    fix: {f.recommendation}")


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
@click.option("--format", "fmt",
              type=click.Choice(["json", "html", "both", "masvs", "cvss", "sbom", "ir"]),
              default="both",
              help="Output format(s). 'masvs' = MASVS coverage matrix; "
                   "'cvss' = CVSS finding draft (Markdown); "
                   "'sbom' = CycloneDX 1.6 SBOM (JSON); "
                   "'ir' = IR findings (Markdown, memory images only).")
def report(path: str, project_dir: str | None, cache_dir: str | None,
           ghidra_home: str | None, out_path: str | None, fmt: str):
    """Run analysis and write a report for the analyst.

    Supported formats: JSON+HTML (default), MASVS coverage matrix,
    CVSS finding draft (Markdown), CycloneDX 1.6 SBOM, IR findings (Markdown).
    """
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

        base = Path(out_path) if out_path else Path.cwd() / f"{Path(path).stem}.report"
        wrote: list[str] = []

        if fmt in ("json", "both"):
            payload = build_report(model, cache)
            json_path = base.with_suffix(".json")
            json_path.write_text(_json.dumps(payload, indent=2))
            wrote.append(str(json_path))
        if fmt in ("html", "both"):
            payload = build_report(model, cache)
            html_path = base.with_suffix(".html")
            html_path.write_text(render_html(payload))
            wrote.append(str(html_path))
        if fmt == "masvs":
            from chimera.detection_engineering.masvs import build_masvs_matrix
            matrix = build_masvs_matrix(model, cache)
            masvs_path = base.with_suffix(".masvs.json")
            masvs_path.write_text(_json.dumps(matrix, indent=2))
            wrote.append(str(masvs_path))
        if fmt == "cvss":
            from chimera.detection_engineering.cvss_findings import (
                build_findings_from_chimera, render_findings_markdown,
            )
            findings = build_findings_from_chimera(model, cache)
            md_path = base.with_suffix(".cvss.md")
            md_path.write_text(render_findings_markdown(findings))
            wrote.append(str(md_path))
        if fmt == "sbom":
            from chimera.detection_engineering.cyclonedx_sbom import build_cyclonedx_sbom
            sbom = build_cyclonedx_sbom(model, cache)
            sbom_path = base.with_suffix(".sbom.json")
            sbom_path.write_text(_json.dumps(sbom, indent=2))
            wrote.append(str(sbom_path))
        if fmt == "ir":
            from chimera.detection_engineering.ir_findings import (
                build_ir_findings, render_ir_findings_markdown,
            )
            findings = build_ir_findings(model, cache)
            md_path = base.with_suffix(".ir.md")
            md_path.write_text(render_ir_findings_markdown(findings))
            wrote.append(str(md_path))

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


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--project-dir", type=click.Path(), default=None)
@click.option("--cache-dir", type=click.Path(), default=None)
@click.option("--ghidra-home", type=str, default=None)
def jni(path: str, project_dir: str | None, cache_dir: str | None,
        ghidra_home: str | None):
    """List JNI bindings (Java native methods + their bound native fns)."""
    asyncio.run(_jni_cmd(path, project_dir, cache_dir, ghidra_home))


async def _jni_cmd(path, project_dir, cache_dir, ghidra_home):
    from chimera.core.config import ChimeraConfig
    from chimera.core.engine import ChimeraEngine
    config = ChimeraConfig(
        project_dir=Path(project_dir) if project_dir else Path.cwd() / "chimera_project",
        cache_dir=Path(cache_dir) if cache_dir else Path.cwd() / "chimera_cache",
        ghidra_home=ghidra_home,
    )
    engine = ChimeraEngine(config)
    try:
        model = await engine.analyze(path)
        natives = [
            f for f in model.functions
            if f.layer == "jvm" and f.metadata and f.metadata.get("is_native")
        ]
        click.echo(f"Native methods: {len(natives)}")
        for f in natives:
            callees = model.get_callees(f.address)
            target = callees[0].address if callees else "(unbound)"
            click.echo(f"  {f.metadata['class_fqcn']}.{f.name}{f.metadata['smali_sig']}  ->  {target}")
    finally:
        await engine.cleanup()


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--project-dir", type=click.Path(), default=None)
@click.option("--cache-dir", type=click.Path(), default=None)
@click.option("--bucket", type=str, default=None,
              help="Filter to a single bucket (process_injection, anti_debug, ...)")
@click.option("--min-score", type=int, default=0,
              help="Hide buckets with score below this threshold")
def imports(path: str, project_dir: str | None, cache_dir: str | None,
            bucket: str | None, min_score: int):
    """List suspicious PE imports with bucket scoring."""
    asyncio.run(_imports_cmd(path, project_dir, cache_dir, bucket, min_score))


async def _imports_cmd(path, project_dir, cache_dir, bucket_filter, min_score):
    from chimera.core.config import ChimeraConfig
    from chimera.core.engine import ChimeraEngine
    config = ChimeraConfig(
        project_dir=Path(project_dir) if project_dir else Path.cwd() / "chimera_project",
        cache_dir=Path(cache_dir) if cache_dir else Path.cwd() / "chimera_cache",
    )
    engine = ChimeraEngine(config)
    try:
        model = await engine.analyze(path)
        from chimera.core.cache import AnalysisCache
        cache = AnalysisCache(config.cache_dir)
        scored = cache.get_json(model.binary.sha256, "pe_imports") or {}
        if not scored:
            click.echo("No PE import scoring available (input may not be a PE).")
            return
        # Sort buckets by weight*score descending
        rows = []
        for b, info in scored.items():
            score = info.get("score", 0)
            weight = info.get("weight", 1.0)
            if score < min_score:
                continue
            if bucket_filter and b != bucket_filter:
                continue
            rows.append((b, score, weight, info.get("imports", [])))
        rows.sort(key=lambda r: -(r[1] * r[2]))
        click.echo(f"PE import scoring for {Path(path).name}:")
        click.echo()
        for b, score, weight, imports_list in rows:
            click.echo(f"  {b:20s} score={score:3d}  weight={weight:>4.1f}")
            preview = ", ".join(imports_list[:6])
            if len(imports_list) > 6:
                preview += f", ... +{len(imports_list) - 6} more"
            click.echo(f"    {preview}")
    finally:
        await engine.cleanup()


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--project-dir", type=click.Path(), default=None)
@click.option("--cache-dir", type=click.Path(), default=None)
def persistence(path: str, project_dir: str | None, cache_dir: str | None):
    """List persistence-relevant strings recovered from a Linux ELF binary."""
    asyncio.run(_persistence_cmd(path, project_dir, cache_dir))


async def _persistence_cmd(path, project_dir, cache_dir):
    from chimera.core.config import ChimeraConfig
    from chimera.core.engine import ChimeraEngine
    from chimera.pipelines.common import detect_platform
    plat = detect_platform(Path(path))
    if plat != "linux_native":
        click.echo(f"chimera persistence: input is not a standalone Linux ELF (detected: {plat})", err=True)
        raise click.exceptions.Exit(1)

    config = ChimeraConfig(
        project_dir=Path(project_dir) if project_dir else Path.cwd() / "chimera_project",
        cache_dir=Path(cache_dir) if cache_dir else Path.cwd() / "chimera_cache",
    )
    engine = ChimeraEngine(config)
    try:
        model = await engine.analyze(path)
        from chimera.core.cache import AnalysisCache
        cache = AnalysisCache(config.cache_dir)
        rows = cache.get_json(model.binary.sha256, "elf_persistence") or []
        if not rows:
            click.echo("No persistence-relevant strings detected.")
            return
        # Group by category
        by_cat: dict[str, list] = {}
        for r in rows:
            by_cat.setdefault(r.get("category", "?"), []).append(r)
        click.echo(f"ELF persistence findings for {Path(path).name}:")
        click.echo()
        for cat in sorted(by_cat):
            entries = by_cat[cat]
            click.echo(f"  [{cat}] {len(entries)} match(es)")
            for e in entries[:6]:
                addr = e.get("string_address") or "—"
                click.echo(f"    {addr:>12}  {e.get('path', '')}")
            if len(entries) > 6:
                click.echo(f"    ... +{len(entries) - 6} more")
    finally:
        await engine.cleanup()


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--project-dir", type=click.Path(), default=None)
@click.option("--cache-dir", type=click.Path(), default=None)
@click.option("--out", "out_path", type=click.Path(), default=None,
              help="Write the rule to this file (default: stdout)")
@click.option("--family", type=str, default=None,
              help="Family/campaign tag for the rule's meta block")
@click.option("--name", "rule_name", type=str, default=None,
              help="Override the rule name (default: Chimera_<sha12>)")
@click.option("--max-strings", type=int, default=12)
@click.option("--max-imports", type=int, default=10)
@click.option("--min-string-length", type=int, default=8)
@click.option("--min-matches", type=int, default=4,
              help="Minimum number of strings/imports that must match")
def yara(path: str, project_dir: str | None, cache_dir: str | None,
         out_path: str | None, family: str | None, rule_name: str | None,
         max_strings: int, max_imports: int, min_string_length: int,
         min_matches: int):
    """Author a draft YARA rule from an analyzed binary.

    Runs the binary through `chimera analyze` (cache-warm reuse) and
    emits a YARA rule built from high-fitness strings + scored imports.
    The output is a *draft* — review and prune before deploying.
    """
    asyncio.run(_yara_cmd(
        path, project_dir, cache_dir, out_path, family, rule_name,
        max_strings, max_imports, min_string_length, min_matches,
    ))


async def _yara_cmd(path, project_dir, cache_dir, out_path, family,
                    rule_name, max_strings, max_imports, min_string_length,
                    min_matches):
    from chimera.core.config import ChimeraConfig
    from chimera.core.engine import ChimeraEngine
    from chimera.detection_engineering.yara_author import author_yara_rule
    config = ChimeraConfig(
        project_dir=Path(project_dir) if project_dir else Path.cwd() / "chimera_project",
        cache_dir=Path(cache_dir) if cache_dir else Path.cwd() / "chimera_cache",
    )
    engine = ChimeraEngine(config)
    try:
        model = await engine.analyze(path)
        rule = author_yara_rule(
            model,
            rule_name=rule_name,
            family=family,
            max_strings=max_strings,
            max_imports=max_imports,
            min_string_length=min_string_length,
            min_string_matches=min_matches,
        )
        if out_path:
            Path(out_path).write_text(rule, encoding="utf-8")
            click.echo(f"Wrote YARA rule to {out_path}")
        else:
            click.echo(rule)
    finally:
        await engine.cleanup()


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--project-dir", type=click.Path(), default=None)
@click.option("--cache-dir", type=click.Path(), default=None)
@click.option("--out", "out_path", type=click.Path(), default=None,
              help="Output file. Default: print summary to stdout.")
@click.option("--format", "fmt",
              type=click.Choice(["table", "json", "stix"]),
              default="table",
              help="Output format. 'stix' emits a STIX 2.1 JSON bundle.")
def ioc(path: str, project_dir: str | None, cache_dir: str | None,
        out_path: str | None, fmt: str):
    """Extract IoCs (URLs, IPs, domains, hashes, crypto addresses)."""
    asyncio.run(_ioc_cmd(path, project_dir, cache_dir, out_path, fmt))


async def _ioc_cmd(path, project_dir, cache_dir, out_path, fmt):
    import json as _json
    from chimera.core.config import ChimeraConfig
    from chimera.core.engine import ChimeraEngine
    from chimera.detection_engineering.ioc_scanner import scan_iocs, summarize
    from chimera.detection_engineering.stix_export import build_stix_bundle
    config = ChimeraConfig(
        project_dir=Path(project_dir) if project_dir else Path.cwd() / "chimera_project",
        cache_dir=Path(cache_dir) if cache_dir else Path.cwd() / "chimera_cache",
    )
    engine = ChimeraEngine(config)
    try:
        model = await engine.analyze(path)
        matches = scan_iocs(model.get_strings())
        if fmt == "table":
            counts = summarize(matches)
            click.echo(f"IoC findings for {Path(path).name}:")
            click.echo()
            for cat in sorted(counts):
                click.echo(f"  {cat:14s} {counts[cat]:>4d}")
            click.echo()
            for cat in sorted({m.category for m in matches}):
                click.echo(f"[{cat}]")
                for m in [x for x in matches if x.category == cat][:25]:
                    addr = m.source_address or "—"
                    click.echo(f"  {m.confidence:>6}  {m.value}  ({addr})")
        elif fmt == "json":
            data = {
                "binary": {"sha256": model.binary.sha256, "path": str(model.binary.path)},
                "summary": summarize(matches),
                "matches": [m.to_dict() for m in matches],
            }
            text = _json.dumps(data, indent=2)
            if out_path:
                Path(out_path).write_text(text, encoding="utf-8")
                click.echo(f"Wrote {out_path}")
            else:
                click.echo(text)
        elif fmt == "stix":
            bundle = build_stix_bundle(model, matches)
            text = _json.dumps(bundle, indent=2)
            if out_path:
                Path(out_path).write_text(text, encoding="utf-8")
                click.echo(f"Wrote STIX bundle to {out_path}")
            else:
                click.echo(text)
    finally:
        await engine.cleanup()


@main.group(invoke_without_command=True)
@click.argument("path", type=click.Path(), required=False)
@click.option("--project-dir", type=click.Path(), default=None)
@click.option("--cache-dir", type=click.Path(), default=None)
@click.pass_context
def memory(ctx, path: str | None,
           project_dir: str | None, cache_dir: str | None):
    """Triage a Linux memory image via Volatility 3.

    Run with no subcommand for the full pipeline; use `pslist`, `netstat`,
    `malfind`, or `findings` to print one section at a time from cache.
    """
    ctx.ensure_object(dict)
    ctx.obj["project_dir"] = project_dir
    ctx.obj["cache_dir"] = cache_dir
    if ctx.invoked_subcommand is None:
        if not path:
            click.echo("chimera memory: PATH is required when no subcommand is given.",
                       err=True)
            raise click.exceptions.Exit(1)
        if not Path(path).exists():
            click.echo(f"chimera memory: path does not exist: {path}", err=True)
            raise click.exceptions.Exit(1)
        ctx.obj["path"] = path
        asyncio.run(_memory_full(path, project_dir, cache_dir))
        return
    ctx.obj["path"] = path  # may be None; subcommands enforce as needed


async def _memory_full(path, project_dir, cache_dir):
    from chimera.core.config import ChimeraConfig
    from chimera.core.engine import ChimeraEngine
    config = ChimeraConfig(
        project_dir=Path(project_dir) if project_dir else Path.cwd() / "chimera_project",
        cache_dir=Path(cache_dir) if cache_dir else Path.cwd() / "chimera_cache",
    )
    engine = ChimeraEngine(config)
    try:
        model = await engine.analyze(path)
        from chimera.core.cache import AnalysisCache
        cache = AnalysisCache(config.cache_dir)
        summary = cache.get_json(model.binary.sha256, "memory_protection") or {}
        click.echo(f"Memory triage for {Path(path).name}:")
        click.echo()
        for key, label in [
            ("process_count", "Processes"),
            ("kernel_thread_count", "  Kernel threads"),
            ("bash_command_count", "Bash commands recovered"),
            ("network_connection_count", "Network connections"),
            ("malfind_hit_count", "Malfind RWX hits"),
            ("kernel_module_count", "Kernel modules"),
            ("hidden_module_count", "  Hidden modules"),
            ("hooked_syscall_count", "  Hooked syscalls"),
            ("persistence_finding_count", "Persistence findings"),
        ]:
            click.echo(f"  {label:32s} {summary.get(key, 0)}")
    finally:
        await engine.cleanup()


def _ensure_path(ctx) -> str:
    path = ctx.obj.get("path")
    if not path:
        click.echo("chimera memory <subcommand>: PATH argument is required",
                   err=True)
        raise click.exceptions.Exit(1)
    return path


@memory.command("pslist")
@click.pass_context
def memory_pslist(ctx):
    """Print the process list from cached memory analysis."""
    asyncio.run(_memory_section(ctx, "vol_pslist", _print_pslist))


@memory.command("netstat")
@click.pass_context
def memory_netstat(ctx):
    """Print recovered network connections."""
    asyncio.run(_memory_section(ctx, "vol_netstat", _print_netstat))


@memory.command("malfind")
@click.pass_context
def memory_malfind(ctx):
    """Print malfind hits (RWX VMA regions)."""
    asyncio.run(_memory_section(ctx, "vol_malfind", _print_malfind))


@memory.command("findings")
@click.pass_context
def memory_findings(ctx):
    """Print auto-stub IR findings."""
    asyncio.run(_memory_findings(ctx))


async def _memory_section(ctx, cache_key, printer):
    path = _ensure_path(ctx)
    from chimera.core.config import ChimeraConfig
    from chimera.core.engine import ChimeraEngine
    config = ChimeraConfig(
        project_dir=Path(ctx.obj.get("project_dir")) if ctx.obj.get("project_dir")
                    else Path.cwd() / "chimera_project",
        cache_dir=Path(ctx.obj.get("cache_dir")) if ctx.obj.get("cache_dir")
                  else Path.cwd() / "chimera_cache",
    )
    engine = ChimeraEngine(config)
    try:
        model = await engine.analyze(path)
        from chimera.core.cache import AnalysisCache
        cache = AnalysisCache(config.cache_dir)
        blob = cache.get_json(model.binary.sha256, cache_key) or {}
        printer(blob)
    finally:
        await engine.cleanup()


async def _memory_findings(ctx):
    path = _ensure_path(ctx)
    from chimera.core.config import ChimeraConfig
    from chimera.core.engine import ChimeraEngine
    from chimera.detection_engineering.ir_findings import (
        build_ir_findings, render_ir_findings_markdown,
    )
    config = ChimeraConfig(
        project_dir=Path(ctx.obj.get("project_dir")) if ctx.obj.get("project_dir")
                    else Path.cwd() / "chimera_project",
        cache_dir=Path(ctx.obj.get("cache_dir")) if ctx.obj.get("cache_dir")
                  else Path.cwd() / "chimera_cache",
    )
    engine = ChimeraEngine(config)
    try:
        model = await engine.analyze(path)
        from chimera.core.cache import AnalysisCache
        cache = AnalysisCache(config.cache_dir)
        findings = build_ir_findings(model, cache)
        click.echo(render_ir_findings_markdown(findings))
    finally:
        await engine.cleanup()


def _print_pslist(blob: dict):
    rows = blob.get("rows") or []
    if not rows:
        click.echo("(no processes recorded — pipeline may not have run)")
        return
    click.echo(f"{'PID':>6}  {'PPID':>6}  {'KTHR':>4}  NAME")
    for r in rows[:200]:
        kthr = "y" if r.get("is_kernel_thread") else " "
        click.echo(f"{r.get('pid', '?'):>6}  {r.get('ppid', '?'):>6}  {kthr:>4}  {r.get('name', '?')}")
    if len(rows) > 200:
        click.echo(f"... +{len(rows) - 200} more")


def _print_netstat(blob: dict):
    rows = blob.get("rows") or []
    if not rows:
        click.echo("(no connections recorded)")
        return
    click.echo(f"{'PROTO':<8}  {'STATE':<14}  {'LOCAL':<24}  {'REMOTE':<24}  PID")
    for r in rows[:200]:
        click.echo(f"{r.get('protocol', '?'):<8}  {r.get('state', '?'):<14}  "
                   f"{r.get('local', '?'):<24}  {r.get('remote', '?'):<24}  {r.get('pid', '?')}")


def _print_malfind(blob: dict):
    rows = blob.get("rows") or []
    if not rows:
        click.echo("(no malfind hits)")
        return
    click.echo(f"{'PID':>6}  {'PROCESS':<16}  {'PROT':<6}  {'START':<16}  END")
    for r in rows[:100]:
        click.echo(f"{r.get('pid', '?'):>6}  {r.get('process', '?'):<16}  "
                   f"{r.get('protection', '?'):<6}  {r.get('start_addr', '?'):<16}  "
                   f"{r.get('end_addr', '?')}")


if __name__ == "__main__":
    main()
