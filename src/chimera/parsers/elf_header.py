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
