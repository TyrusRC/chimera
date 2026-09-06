"""Walk a Windows PE binary's headers via pefile and extract analyst-relevant facts.

Returns a `PEHeaderInfo` payload containing the bits the pipeline cares
about: machine, sections (with entropy), imports, exports, plus a few
boolean flags (is_dotnet, has_authenticode_signature, has_tls_callbacks).
We deliberately stop at metadata extraction — actual byte-level analysis
is the disassembler's job.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from pathlib import Path

import pefile


_MACHINE_MAP = {
    0x014c: "x86",
    0x0200: "ia64",
    0x8664: "x86_64",
    0xaa64: "arm64",
    0x01c0: "arm",
    0x01c4: "armnt",
}


@dataclass
class PESection:
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    characteristics: int
    entropy: float
    is_executable: bool
    is_writable: bool
    is_readable: bool


@dataclass
class PEHeaderInfo:
    machine: str
    is_dll: bool
    is_dotnet: bool
    pe_class: str          # "PE32" | "PE32+"
    timestamp: int
    entry_point: int
    image_base: int
    size_of_code: int
    sections: list[PESection]
    imports: list[dict]    # plain dicts to avoid the ImportEntry import dance
    exports: list[str]
    has_tls_callbacks: bool
    has_resources: bool
    has_authenticode_signature: bool
    debug_directory_count: int


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    e = 0.0
    for c in counts:
        if c == 0:
            continue
        p = c / total
        e -= p * math.log2(p)
    return e


def entropy_anomalies(sections, file_size: int, *,
                      threshold: float = 7.2, min_fraction: float = 0.10) -> list[dict]:
    """Flag sections that look like an encrypted/compressed payload.

    A section is anomalous when its entropy is near-random (``>= threshold``)
    *and* it is a meaningful fraction of the file (``>= min_fraction``), so a
    ~1.9MB `.data` blob at 7.96 entropy is surfaced while a tiny high-entropy
    resource stub is not. This is the single most actionable structural fact
    on a hand-packed sample, so `analyze` reports it rather than only counting.
    """
    out: list[dict] = []
    for s in sections:
        frac = (s.raw_size / file_size) if file_size else 0.0
        if s.entropy >= threshold and frac >= min_fraction:
            out.append({
                "name": s.name,
                "entropy": round(s.entropy, 2),
                "raw_size": s.raw_size,
                "fraction": round(frac, 3),
            })
    return out


def parse_pe(path: Path) -> PEHeaderInfo:
    """Parse a PE file via `pefile`. Caller is responsible for ensuring
    the file is actually a PE (use `_classify_pe` from `chimera.model.binary`).
    Raises pefile.PEFormatError on truly malformed input.
    """
    pe = pefile.PE(str(path), fast_load=False)
    try:
        machine = _MACHINE_MAP.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))

        is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)

        # PE32 (Magic 0x10b) vs PE32+ (Magic 0x20b)
        opt_magic = pe.OPTIONAL_HEADER.Magic
        pe_class = "PE32+" if opt_magic == 0x20b else "PE32"

        # CLR header lives at DataDirectory[14]
        clr = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
        is_dotnet = clr.VirtualAddress != 0 and clr.Size != 0

        sections: list[PESection] = []
        for s in pe.sections:
            data = s.get_data()
            chars = s.Characteristics
            sections.append(PESection(
                name=s.Name.rstrip(b"\x00").decode("ascii", errors="replace"),
                virtual_address=s.VirtualAddress,
                virtual_size=s.Misc_VirtualSize,
                raw_size=s.SizeOfRawData,
                characteristics=chars,
                entropy=_shannon_entropy(data),
                is_executable=bool(chars & 0x20000000),
                is_writable=bool(chars & 0x80000000),
                is_readable=bool(chars & 0x40000000),
            ))

        imports: list[dict] = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("ascii", errors="replace") if entry.dll else ""
                for imp in entry.imports:
                    name = imp.name.decode("ascii", errors="replace") if imp.name else ""
                    imports.append({
                        "dll": dll,
                        "name": name,
                        "address": hex(imp.address) if imp.address else None,
                        "ordinal": imp.ordinal if not imp.name else None,
                    })

        exports: list[str] = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    exports.append(exp.name.decode("ascii", errors="replace"))

        # DataDirectory indices: 6 = DEBUG, 9 = TLS, 14 = COM_DESCRIPTOR (handled), 4 = SECURITY
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        has_authenticode_signature = sec_dir.VirtualAddress != 0 and sec_dir.Size != 0

        tls_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[9]
        has_tls_callbacks = tls_dir.VirtualAddress != 0 and tls_dir.Size != 0

        debug_count = 0
        if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
            debug_count = len(pe.DIRECTORY_ENTRY_DEBUG)

        has_resources = hasattr(pe, "DIRECTORY_ENTRY_RESOURCE")

        return PEHeaderInfo(
            machine=machine,
            is_dll=is_dll,
            is_dotnet=is_dotnet,
            pe_class=pe_class,
            timestamp=pe.FILE_HEADER.TimeDateStamp,
            entry_point=pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            image_base=pe.OPTIONAL_HEADER.ImageBase,
            size_of_code=pe.OPTIONAL_HEADER.SizeOfCode,
            sections=sections,
            imports=imports,
            exports=exports,
            has_tls_callbacks=has_tls_callbacks,
            has_resources=has_resources,
            has_authenticode_signature=has_authenticode_signature,
            debug_directory_count=debug_count,
        )
    finally:
        pe.close()
