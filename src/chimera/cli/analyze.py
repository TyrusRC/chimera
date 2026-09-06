"""chimera.cli — analyze commands."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

import click

from chimera import __version__
from chimera.cli._root import main

logger = logging.getLogger(__name__)



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
        from chimera.core.cache import AnalysisCache
        cache = AnalysisCache(config.cache_dir)
        sha = model.binary.sha256

        click.echo("Analysis complete:")
        click.echo(f"  Platform:  {model.binary.platform.value}")
        click.echo(f"  Format:    {model.binary.format.value}")
        click.echo(f"  Framework: {_framework_label(model, cache, sha)}")
        click.echo(f"  SHA256:    {sha[:16]}...")
        click.echo(f"  Functions: {len(model.functions)}")
        click.echo(f"  Strings:   {len(model.get_strings())}")

        # Per-native-lib outcomes from the cache so the analyst can see
        # which library each backend actually analyzed (not just "ghidra
        # ran"). Walks the cache for r2_<name>/ghidra_<name> entries.
        per_lib = _per_native_lib_summary(cache, sha)
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

        # Surface high-entropy sections — the single most actionable structural
        # fact on a hand-packed sample (an encrypted/compressed payload blob).
        pe_flags = cache.get_json(sha, "pe_flags") or {}
        for a in pe_flags.get("entropy_anomalies", []):
            click.echo()
            click.echo(
                f"  ⚠ High-entropy section {a['name']}: entropy {a['entropy']} over "
                f"{a['fraction'] * 100:.0f}% of the file — likely encrypted/compressed payload"
            )

        # If a disassembler's function walk was defeated (e.g. an ILT-heavy
        # /INCREMENTAL PE64), .pdata gives the authoritative count — say so.
        pdf = cache.get_json(sha, "pdata_functions") or {}
        if pdf.get("pdata_count"):
            click.echo()
            click.echo(
                f"  ⚠ Function recovery incomplete: disassembler found "
                f"{pdf['r2_count']} (~import count) but .pdata lists "
                f"{pdf['pdata_count']} — backfilled {pdf['backfilled']} "
                "(ILT-obscured call graph)."
            )

        # If a native PE was triaged without a decompiler, say so plainly so the
        # function count isn't mistaken for a complete, decompiled view.
        unavailable_names = {a.name().lower() for a in engine.registry.all_registered()
                             if not a.is_available()}
        fmt = model.binary.format.value
        if "ghidra" in unavailable_names and fmt.startswith("pe"):
            click.echo()
            click.echo("  ⚠ No decompiler (Ghidra) available — functions are a shallow "
                       "r2 sweep with no library/user split; treat as incomplete.")

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



def _framework_label(model, cache=None, sha=None) -> str:
    """Honest framework label for the analyze summary.

    `Framework.NONE` becomes "none (jvm/kotlin)" on Android and
    "none (objc/swift)" on iOS so the analyst sees what code layer they're
    actually looking at, not just an enum value that reads as "C/C++". A
    fingerprinted native runtime (e.g. VB6/twinBASIC) carries its detail.
    """
    fw = model.binary.framework.value
    plat = model.binary.platform.value
    if fw == "none":
        if plat == "android":
            return "none (jvm/kotlin)"
        if plat == "ios":
            return "none (objc/swift)"
    if cache is not None and sha:
        rt = cache.get_json(sha, "native_runtime") or {}
        if rt.get("detail"):
            return f"{fw} ({rt['detail']})"
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
