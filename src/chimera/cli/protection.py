"""chimera.cli — protection commands."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import click

from chimera.cli._root import main

logger = logging.getLogger(__name__)



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

        native_profile = cache.get_json(model.binary.sha256, "native_protection") or {}
        merge_native_profile(profile, native_profile)

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
        if profile.has_anti_debug and native_profile.get("anti_debug_low_confidence"):
            click.echo("      ↳ low confidence: only CRT-ambiguous indicators "
                       "(IsDebuggerPresent / OutputDebugString) — the MSVC "
                       "runtime imports these on its own")
        _emit_protection_line("SSL pinning:        ", profile.has_ssl_pinning,
                              hits_by_cat.get("ssl_pinning"))
        _emit_protection_line("Integrity checks:   ", profile.has_integrity_check,
                              hits_by_cat.get("integrity"))
        click.echo(f"  Packer:              {'YES (' + (profile.packer_name or '?') + ')' if profile.has_packer else 'no'}")
        # Native-only signals — no field on the (mobile-shaped) profile, so
        # they'd otherwise be invisible on a PE/ELF target.
        native_extra = [
            label for key, label in (
                ("has_anti_vm", "anti-VM"),
                ("has_self_inject", "self-injection"),
                ("has_persistence_strings", "persistence"),
            ) if native_profile.get(key)
        ]
        if native_extra:
            click.echo(f"  Native signals:      {', '.join(native_extra)}")
        if native_profile.get("high_entropy_section_count"):
            click.echo("  High-entropy sects:  "
                       f"{native_profile['high_entropy_section_count']}")
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



def merge_native_profile(profile, native_profile: dict) -> None:
    """Fold a cached PE/ELF `native_detector` profile into a ProtectionProfile.

    The PE/ELF pipelines cache their result under "native_protection"
    (singular); Android caches an unrelated blob under "native_protections"
    (plural). This command previously read only the plural key, so on a
    native target every PE/ELF signal was dropped — a binary importing
    IsDebuggerPresent still printed "Anti-debug: no", because the mobile
    string detector never sees a PE import table.

    Merges upward only: a protection already found by another source is
    never cleared by a native profile that missed it.
    """
    if not native_profile:
        return
    if native_profile.get("has_anti_debug"):
        profile.has_anti_debug = True
    if native_profile.get("has_integrity_check"):
        profile.has_integrity_check = True
    if native_profile.get("packer"):
        profile.has_packer = True
        profile.packer_name = profile.packer_name or native_profile["packer"]
    for technique in native_profile.get("obfuscation") or []:
        if technique not in profile.obfuscation_techniques:
            profile.obfuscation_techniques.append(technique)
    profile.details.extend(native_profile.get("details") or [])


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
