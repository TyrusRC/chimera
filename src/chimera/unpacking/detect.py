"""Packer detection — YARA rule hits first, section-entropy heuristic second.

The YARA pass uses chimera's bundled `pe_packers.yar` / `elf_packers.yar`
which already discriminate UPX / ASPack / VMProtect / Themida / MPRESS /
PECompact / MEW / kkrunchy. When YARA isn't available we fall back to a
heuristic: pack-protected binaries almost always have at least one
executable section with byte-entropy > 7.0, often paired with mismatched
section names (``UPX0``, ``.vmp0``, etc.).

Detection never raises. ``Detection.packer`` is None when nothing rang
the bell — the CLI handles that case and tells the analyst we found
nothing actionable, rather than guessing.
"""

from __future__ import annotations

import logging
import math
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


# Suspicious section-name patterns indexed by their telltale packer.
# We intentionally keep this conservative so we don't false-positive on
# packers our YARA pack already covers.
_SECTION_NAME_HINTS: dict[str, list[re.Pattern[str]]] = {
    "UPX": [re.compile(r"^UPX[0-9!]?$", re.I)],
    "ASPack": [re.compile(r"^\.aspack$", re.I), re.compile(r"^\.adata$", re.I)],
    "VMProtect": [re.compile(r"^\.vmp[0-9]$", re.I)],
    "Themida": [re.compile(r"^\.themida$", re.I), re.compile(r"^\.winlicense$", re.I)],
    "MPRESS": [re.compile(r"^\.MPRESS[0-9]$", re.I)],
    "PECompact": [re.compile(r"^pec[0-9]+$", re.I)],
    "Enigma": [re.compile(r"^\.enigma[0-9]?$", re.I)],
}


@dataclass
class Detection:
    """Result of a packer-detection pass."""
    packer: Optional[str]
    signals: list[str] = field(default_factory=list)
    high_entropy_sections: int = 0
    suspicious_section_names: list[str] = field(default_factory=list)


def detect_packer(binary_path: Path) -> Detection:
    """Run YARA + entropy heuristics; return the first decisive signal.

    The YARA path is preferred because the rules carry vendor metadata
    (``packer = "Themida/WinLicense"``) the heuristic can't match. We
    still run the heuristic when YARA is silent so analysts get *some*
    actionable signal on every input.
    """
    binary_path = Path(binary_path)
    signals: list[str] = []
    packer: Optional[str] = None

    yara_hit = _yara_detect(binary_path)
    if yara_hit:
        packer = yara_hit
        signals.append(f"yara:{yara_hit}")

    section_packer, suspicious_names = _section_name_hint(binary_path)
    if section_packer and not packer:
        packer = section_packer
        signals.append(f"section_name:{section_packer}")
    if section_packer and packer == section_packer:
        # We already have it from YARA, but record the corroborating signal.
        signals.append(f"section_name:{section_packer}")

    high_entropy = _high_entropy_section_count(binary_path)
    if high_entropy:
        signals.append(f"high_entropy_sections={high_entropy}")
    if packer is None and high_entropy >= 2:
        # Two or more high-entropy executable sections is a strong tell
        # for an unknown packer; flag it generically so the user can
        # supply --packer manually if they recognise it.
        packer = "unknown"
        signals.append("high_entropy_unattributed")

    return Detection(
        packer=packer if packer != "unknown" else None,
        signals=signals,
        high_entropy_sections=high_entropy,
        suspicious_section_names=suspicious_names,
    )


# ---------------------------------------------------------------------------
# YARA pass
# ---------------------------------------------------------------------------


def _yara_detect(path: Path) -> Optional[str]:
    """Run the bundled YARA packer ruleset and return the first match.

    Uses the chimera YaraAdapter's pre-compiled rules so we benefit from
    its bundled-rule discovery without duplicating the loader logic. The
    adapter's ``analyze`` is async; we synchronously call its underlying
    compiled rules to avoid spinning a sub-loop here.
    """
    try:
        from chimera.adapters.yara_adapter import YaraAdapter
    except Exception as exc:
        logger.debug("YaraAdapter import failed: %s", exc)
        return None
    adapter = YaraAdapter()
    if not adapter.is_available():
        return None
    try:
        rules = adapter._load_rules()
    except Exception as exc:
        logger.debug("YaraAdapter rules load failed: %s", exc)
        return None
    try:
        matches = rules.match(str(path), timeout=10)
    except Exception as exc:
        logger.debug("yara match failed for %s: %s", path, exc)
        return None
    for m in matches:
        meta = getattr(m, "meta", None) or {}
        if meta.get("kind") == "commercial_packer":
            packer = meta.get("packer") or m.rule
            return str(packer)
    return None


# ---------------------------------------------------------------------------
# Section-name + entropy heuristics
# ---------------------------------------------------------------------------


def _section_name_hint(path: Path) -> tuple[Optional[str], list[str]]:
    """PE-only: look at section headers for telltale names."""
    suspicious: list[str] = []
    try:
        import pefile
    except ImportError:
        return None, suspicious
    if not _looks_like_pe(path):
        return None, suspicious
    try:
        pe = pefile.PE(str(path), fast_load=True)
    except Exception:
        return None, suspicious
    try:
        for sec in pe.sections:
            name = sec.Name.decode(errors="replace").rstrip("\x00")
            for packer, patterns in _SECTION_NAME_HINTS.items():
                if any(p.match(name) for p in patterns):
                    suspicious.append(name)
                    return packer, suspicious
    finally:
        pe.close()
    return None, suspicious


def _high_entropy_section_count(path: Path) -> int:
    """Return the number of executable sections with byte-entropy > 7.0.

    PE: walks IMAGE_SECTION_HEADER.Characteristics for ``IMAGE_SCN_MEM_EXECUTE``.
    ELF: walks program headers; any PT_LOAD with PF_X flag.
    Mach-O and unknown formats return 0 — the heuristic isn't reliable enough
    there to surface.
    """
    if _looks_like_pe(path):
        return _pe_high_entropy_count(path)
    if _looks_like_elf(path):
        return _elf_high_entropy_count(path)
    return 0


def _pe_high_entropy_count(path: Path) -> int:
    try:
        import pefile
    except ImportError:
        return 0
    try:
        pe = pefile.PE(str(path), fast_load=True)
    except Exception:
        return 0
    count = 0
    try:
        IMAGE_SCN_MEM_EXECUTE = 0x20000000
        for sec in pe.sections:
            if not (sec.Characteristics & IMAGE_SCN_MEM_EXECUTE):
                continue
            data = sec.get_data()
            if _entropy(data) > 7.0:
                count += 1
    finally:
        pe.close()
    return count


def _elf_high_entropy_count(path: Path) -> int:
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        return 0
    count = 0
    try:
        with open(path, "rb") as fh:
            elf = ELFFile(fh)
            for seg in elf.iter_segments():
                if seg["p_type"] != "PT_LOAD":
                    continue
                if not (seg["p_flags"] & 0x1):  # PF_X
                    continue
                data = seg.data()
                if _entropy(data) > 7.0:
                    count += 1
    except Exception:
        return count
    return count


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / total
            ent -= p * math.log2(p)
    return ent


def _looks_like_pe(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            head = fh.read(2)
    except OSError:
        return False
    return head == b"MZ"


def _looks_like_elf(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            head = fh.read(4)
    except OSError:
        return False
    return head == b"\x7fELF"
