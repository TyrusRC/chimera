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
    #: Evidence says "packed", but nothing names *which* packer. Kept separate
    #: from `packer` because that field drives `unpacker_for()` and must stay a
    #: name we can actually act on — while an analyst still needs to know the
    #: binary looks packed rather than reading `packer=(none)` as "it's clean".
    suspected_packed: bool = False


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

    structural = _pe_structural_anomalies(binary_path)
    signals.extend(structural)

    # Only claim "suspected" when we couldn't attribute a name — a named
    # packer is already the stronger, actionable answer.
    suspected = False
    if packer is None and (high_entropy >= 2 or structural):
        suspected = True
        signals.append("packed_unattributed")

    return Detection(
        packer=packer,
        signals=signals,
        high_entropy_sections=high_entropy,
        suspicious_section_names=suspicious_names,
        suspected_packed=suspected,
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


def _pe_structural_anomalies(path: Path) -> list[str]:
    """PE section-table shapes that imply a runtime unpacking stub.

    These catch packers the YARA pack and the name table both miss (renamed
    stubs, bespoke protectors), because they key on what a packer must *do*
    rather than what it is called:

    * an executable section with no bytes on disk has to be written at
      runtime — there is nothing else it could be;
    * a *code* section whose virtual size far exceeds its raw size means
      the same thing, with the stub decompressing into the slack.

    Deliberately *not* included, each having been measured against a
    labeled corpus and rejected:

    * high-entropy resources — compressed icons fire constantly on clean
      binaries;
    * duplicate section names — scored 0 true positives against 2 false
      positives (real linkers do emit repeated `.idata`/custom sections),
      so it was pure noise;
    * virtual-size-exceeds-raw on *data* sections — that is just BSS.
    """
    anomalies: list[str] = []
    try:
        import pefile
    except ImportError:
        return anomalies
    if not _looks_like_pe(path):
        return anomalies
    try:
        pe = pefile.PE(str(path), fast_load=True)
    except Exception:
        return anomalies
    try:
        IMAGE_SCN_CNT_CODE = 0x00000020
        IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
        IMAGE_SCN_MEM_EXECUTE = 0x20000000
        for sec in pe.sections:
            name = sec.Name.decode(errors="replace").rstrip("\x00")
            # A section the file itself declares as *code* while shipping no
            # bytes on disk is a contradiction — something must write it at
            # runtime. Executable-but-uninitialized is NOT a contradiction
            # (that is a .bss-like region a linker may legitimately mark
            # executable), and on a labeled corpus it was the sole source of
            # false positives, so it is excluded.
            declares_code = bool(sec.Characteristics & IMAGE_SCN_CNT_CODE) or (
                bool(sec.Characteristics & IMAGE_SCN_MEM_EXECUTE)
                and not sec.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA
            )
            if declares_code and sec.SizeOfRawData == 0 and sec.Misc_VirtualSize > 0:
                anomalies.append(f"zero_raw_exec_section:{name or '<unnamed>'}")
            elif (declares_code
                  and sec.SizeOfRawData > 0
                  and sec.Misc_VirtualSize > 4 * sec.SizeOfRawData):
                # Code only. A *data* section routinely has a virtual size far
                # past its raw size — that is how PE carries BSS, with the
                # uninitialized tail merged into .data — and on a labeled
                # corpus applying this to any section dropped precision to
                # 0.56, every false positive being .data/.idata/.reloc.
                anomalies.append(f"virtual_size_exceeds_raw:{name or '<unnamed>'}")
    except Exception:
        return anomalies
    finally:
        pe.close()
    return anomalies


# Shannon entropy over n bytes is bounded by log2(n), so a small buffer of
# varied bytes scores near-maximum for free: 256 distinct bytes measure a
# perfect 8.0. An ordinary jump or thunk table would therefore read as
# "packed". Below this many bytes the estimate is sample noise, so we don't
# count it either way.
_MIN_ENTROPY_SAMPLE = 1024


def _high_entropy_section_count(path: Path) -> int:
    """Return the number of executable sections with byte-entropy > 7.0.

    Sections smaller than `_MIN_ENTROPY_SAMPLE` are skipped — see above.

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
            if len(data) < _MIN_ENTROPY_SAMPLE:
                continue
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
                if len(data) < _MIN_ENTROPY_SAMPLE:
                    continue
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
