"""Parse a Linux ELF binary's headers via pyelftools.

Returns an ELFHeaderInfo payload covering the static-triage attributes:
file class, architecture, dynamic linker, NEEDED libs, RPATH/RUNPATH,
SONAME, RELRO/NX/PIE flags, section list, symbol presence.

Like pe_header.py, this stops at metadata extraction. Disassembly is r2/
Ghidra's job.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection
from elftools.elf.constants import P_FLAGS


_MACHINE_MAP = {
    "EM_386": "x86",
    "EM_X86_64": "x86_64",
    "EM_AARCH64": "arm64",
    "EM_ARM": "arm",
    "EM_MIPS": "mips",
    "EM_RISCV": "riscv",
    "EM_PPC": "ppc",
    "EM_PPC64": "ppc64",
}


@dataclass
class ELFSection:
    name: str
    size: int
    flags: int
    is_executable: bool
    is_writable: bool


@dataclass
class ELFHeaderInfo:
    file_class: str            # "ELF32" | "ELF64"
    machine: str               # "x86_64", "arm64", ...
    e_type: str                # "ET_EXEC" | "ET_DYN" | "ET_REL" | "ET_CORE"
    entry_point: int
    dynamic_linker: str | None
    needed: list[str] = field(default_factory=list)
    rpath: list[str] = field(default_factory=list)
    runpath: list[str] = field(default_factory=list)
    soname: str | None = None
    relro: str = "none"        # "none" | "partial" | "full"
    nx: bool = False
    pie: bool = False
    sections: list[ELFSection] = field(default_factory=list)
    has_symbols: bool = False
    is_stripped: bool = True
    #: True when this ELF targets Android (bionic linker or Android note).
    is_android: bool = False
    #: ARM AArch64 pointer-authentication (PAC) advertised in .note.gnu.property.
    pac: bool = False
    #: ARM branch-target-identification (BTI) advertised in .note.gnu.property.
    bti: bool = False
    #: ARM MTE / MemTag mode from .note.android.memtag: None, or one of
    #: "none"/"async"/"sync", optionally suffixed with "+heap"/"+stack".
    memtag: str | None = None


def _decode_memtag(desc: bytes) -> str:
    """Decode an Android `.note.android.memtag` descriptor (first LE u32).

    Bits [1:0] = mode (0 none, 1 async, 2 sync); bit2 = heap; bit3 = stack.
    """
    if len(desc) < 4:
        return "none"
    val = int.from_bytes(desc[:4], "little")
    mode = {0: "none", 1: "async", 2: "sync", 3: "sync"}.get(val & 0b11, "none")
    scopes = []
    if val & 0b100:
        scopes.append("heap")
    if val & 0b1000:
        scopes.append("stack")
    return mode + ("+" + "+".join(scopes) if scopes else "")


def _scan_notes(elf, info: ELFHeaderInfo) -> None:
    """Read `.note.android.memtag` (MTE) and `.note.gnu.property` (BTI/PAC).

    Parses raw note payloads rather than a pyelftools note API so behaviour
    is stable across pyelftools versions. Note layout (per ELF spec):
    namesz(4) descsz(4) type(4), then name and desc, each 4-byte aligned.
    """
    for sec in elf.iter_sections():
        if sec["sh_type"] != "SHT_NOTE":
            continue
        data = sec.data()
        off = 0
        while off + 12 <= len(data):
            namesz, descsz, ntype = (
                int.from_bytes(data[off:off + 4], "little"),
                int.from_bytes(data[off + 4:off + 8], "little"),
                int.from_bytes(data[off + 8:off + 12], "little"),
            )
            name_start = off + 12
            name = data[name_start:name_start + namesz].rstrip(b"\x00")
            desc_start = name_start + ((namesz + 3) & ~3)
            desc = data[desc_start:desc_start + descsz]
            off = desc_start + ((descsz + 3) & ~3)

            if sec.name == ".note.android.ident" or name == b"Android":
                info.is_android = True
            if sec.name == ".note.android.memtag":
                info.memtag = _decode_memtag(desc)
            if name == b"GNU" and ntype == 5:  # NT_GNU_PROPERTY_TYPE_0
                _parse_gnu_property(desc, info)


def _parse_gnu_property(desc: bytes, info: ELFHeaderInfo) -> None:
    """Extract AArch64 BTI/PAC from a .note.gnu.property descriptor.

    Property array entries: pr_type(4) pr_datasz(4) pr_data(pr_datasz),
    padded to 8 bytes. GNU_PROPERTY_AARCH64_FEATURE_1_AND == 0xc0000000;
    its first data word carries bit0=BTI, bit1=PAC.
    """
    p = 0
    while p + 8 <= len(desc):
        pr_type = int.from_bytes(desc[p:p + 4], "little")
        pr_datasz = int.from_bytes(desc[p + 4:p + 8], "little")
        pdata = desc[p + 8:p + 8 + pr_datasz]
        if pr_type == 0xC0000000 and len(pdata) >= 4:
            feat = int.from_bytes(pdata[:4], "little")
            info.bti = bool(feat & 0b1)
            info.pac = bool(feat & 0b10)
        p += 8 + ((pr_datasz + 7) & ~7)


def parse_elf(path: Path) -> ELFHeaderInfo:
    """Parse an ELF file via pyelftools. Caller ensures the file is ELF
    (use `_classify_elf_context` from `chimera.pipelines.common`).

    Raises ELFError on malformed input.
    """
    with open(path, "rb") as fh:
        elf = ELFFile(fh)
        file_class = "ELF64" if elf.elfclass == 64 else "ELF32"
        machine_id = elf.header["e_machine"]
        machine = _MACHINE_MAP.get(machine_id, machine_id)
        e_type = elf.header["e_type"]
        entry_point = elf.header["e_entry"]

        info = ELFHeaderInfo(
            file_class=file_class,
            machine=machine,
            e_type=e_type,
            entry_point=entry_point,
            dynamic_linker=None,
        )

        # Walk segments for PT_INTERP (dynamic linker), PT_GNU_RELRO (relro),
        # PT_GNU_STACK (NX bit).
        has_relro_segment = False
        for segment in elf.iter_segments():
            t = segment["p_type"]
            if t == "PT_INTERP":
                interp = segment.get_interp_name()
                if interp:
                    info.dynamic_linker = interp
            elif t == "PT_GNU_RELRO":
                has_relro_segment = True
            elif t == "PT_GNU_STACK":
                info.nx = not (segment["p_flags"] & P_FLAGS.PF_X)

        # Walk dynamic section for NEEDED, RPATH, RUNPATH, SONAME, FLAGS.
        bind_now = False
        for section in elf.iter_sections():
            if isinstance(section, DynamicSection):
                for tag in section.iter_tags():
                    t = tag.entry.d_tag
                    if t == "DT_NEEDED":
                        info.needed.append(tag.needed)
                    elif t == "DT_RPATH":
                        info.rpath.extend([s for s in tag.rpath.split(":") if s])
                    elif t == "DT_RUNPATH":
                        info.runpath.extend([s for s in tag.runpath.split(":") if s])
                    elif t == "DT_SONAME":
                        info.soname = tag.soname
                    elif t == "DT_BIND_NOW":
                        bind_now = True
                    elif t == "DT_FLAGS":
                        if tag.entry.d_val & 0x8:  # DF_BIND_NOW
                            bind_now = True
                    elif t == "DT_FLAGS_1":
                        if tag.entry.d_val & 0x1:  # DF_1_NOW
                            bind_now = True

        if has_relro_segment and bind_now:
            info.relro = "full"
        elif has_relro_segment:
            info.relro = "partial"
        else:
            info.relro = "none"

        # PIE: ET_DYN is shared object OR PIE executable. Distinguish via
        # PT_INTERP presence (PIE has it; libraries don't).
        if e_type == "ET_DYN" and info.dynamic_linker is not None:
            info.pie = True

        # Android: bionic dynamic linker, or an Android-owned note.
        if info.dynamic_linker and "/system/bin/linker" in info.dynamic_linker:
            info.is_android = True

        # MTE / BTI / PAC live in ELF notes.
        try:
            _scan_notes(elf, info)
        except Exception:
            pass

        # Sections + symbols
        for sec in elf.iter_sections():
            flags = sec["sh_flags"]
            info.sections.append(ELFSection(
                name=sec.name,
                size=sec["sh_size"],
                flags=flags,
                is_executable=bool(flags & 0x4),    # SHF_EXECINSTR
                is_writable=bool(flags & 0x1),       # SHF_WRITE
            ))
            if sec.name == ".symtab":
                info.has_symbols = True
                info.is_stripped = False
            elif sec.name == ".dynsym" and not info.has_symbols:
                info.has_symbols = True
                # not necessarily stripped; .symtab missing is what marks it

        if not any(s.name == ".symtab" for s in info.sections):
            info.is_stripped = True

        return info
