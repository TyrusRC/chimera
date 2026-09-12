"""ELF core-dump triage — maps, registers, and address→module for a process core.

chimera could analyze the backdoored library in the Flare-On sshd challenge but
had NO way to touch the CORE DUMP that captured the attack — yet the whole solve
lived there: which module the crash `rip`/return address falls in, the register
state, and the attacker payload resident in memory. `memory` (Volatility) is for
whole-OS images, not a userspace ELF core. This fills that: parse the core's
PT_LOAD ranges, the NT_FILE module mappings and the NT_PRSTATUS registers (per
thread), resolve an address to `module+offset`, and read/search process memory.

x86-64 focused (the NT_PRSTATUS register layout is arch-specific); other arches
still get maps + memory read/search, just no decoded registers.
"""
from __future__ import annotations

import struct
from pathlib import Path

# user_regs_struct order on x86-64; pr_reg sits at offset 112 in elf_prstatus.
_X86_64_REGS = ("r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi "
                "orig_rax rip cs eflags rsp ss fs_base gs_base ds es fs gs").split()
_PRSTATUS_REG_OFFSET = 112


class CoreDump:
    """A parsed ELF core dump. Raises ValueError on a non-core / unreadable file."""

    def __init__(self, path: str):
        try:
            from elftools.elf.elffile import ELFFile
        except Exception as exc:  # pragma: no cover
            raise ValueError("pyelftools not installed") from exc
        self.path = str(path)
        self._fh = open(self.path, "rb")
        try:
            self.elf = ELFFile(self._fh)
            e_type = self.elf.header["e_type"]
        except Exception as exc:
            self._fh.close()
            raise ValueError(f"not a parseable ELF file: {exc}") from exc
        if e_type != "ET_CORE":
            self._fh.close()
            raise ValueError("not an ELF core dump (e_type != ET_CORE)")
        self.machine = self.elf.header["e_machine"]
        self.loads: list[dict] = []
        for s in self.elf.iter_segments():
            if s["p_type"] == "PT_LOAD":
                self.loads.append({"vaddr": s["p_vaddr"], "off": s["p_offset"],
                                   "filesz": s["p_filesz"], "memsz": s["p_memsz"],
                                   "flags": s["p_flags"]})
        self.mappings: list[dict] = []
        self.threads: list[dict] = []
        self._parse_notes()

    def _parse_notes(self):
        for seg in self.elf.iter_segments():
            if seg["p_type"] != "PT_NOTE":
                continue
            for n in seg.iter_notes():
                t = n["n_type"]
                if t == "NT_FILE":
                    d = n["n_desc"]
                    ents = getattr(d, "Elf_Nt_File_Entry", [])
                    names = getattr(d, "filename", [])
                    for e, name in zip(ents, names):
                        self.mappings.append({
                            "start": e["vm_start"], "end": e["vm_end"],
                            "file_offset": e["page_offset"] * getattr(d, "page_size", 4096),
                            "path": name.decode("latin-1", "replace") if isinstance(name, bytes) else str(name)})
                elif t == "NT_PRSTATUS" and self.machine == "EM_X86_64":
                    b = n["n_desc"]
                    if len(b) >= _PRSTATUS_REG_OFFSET + 27 * 8:
                        regs = struct.unpack_from("<27Q", b, _PRSTATUS_REG_OFFSET)
                        self.threads.append(dict(zip(_X86_64_REGS, regs)))

    # ---- address resolution / memory ----------------------------------

    def address_to_module(self, addr: int):
        """Return (path, offset_in_module) for `addr`, or None."""
        hits = [m for m in self.mappings if m["start"] <= addr < m["end"]]
        if not hits:
            return None
        m = min(hits, key=lambda x: x["start"])
        base = min(x["start"] for x in self.mappings if x["path"] == m["path"])
        return (m["path"], addr - base)

    def read(self, addr: int, size: int) -> bytes | None:
        for ld in self.loads:
            if ld["vaddr"] <= addr < ld["vaddr"] + ld["filesz"]:
                start = ld["off"] + (addr - ld["vaddr"])
                avail = ld["off"] + ld["filesz"] - start
                self._fh.seek(start)
                return self._fh.read(min(size, avail))
        return None

    def search(self, needle: bytes, limit: int = 64) -> list[int]:
        """Find `needle` across mapped memory; returns virtual addresses."""
        out: list[int] = []
        for ld in self.loads:
            if not ld["filesz"]:
                continue
            self._fh.seek(ld["off"])
            data = self._fh.read(ld["filesz"])
            pos = data.find(needle)
            while pos != -1 and len(out) < limit:
                out.append(ld["vaddr"] + pos)
                pos = data.find(needle, pos + 1)
            if len(out) >= limit:
                break
        return out

    def modules(self) -> list[dict]:
        """Deduplicated module list (min start .. max end per path)."""
        by_path: dict[str, dict] = {}
        for m in self.mappings:
            e = by_path.setdefault(m["path"], {"path": m["path"], "start": m["start"], "end": m["end"]})
            e["start"] = min(e["start"], m["start"])
            e["end"] = max(e["end"], m["end"])
        return sorted(by_path.values(), key=lambda x: x["start"])

    def triage(self) -> dict:
        crash = None
        if self.threads:
            rip = self.threads[0].get("rip", 0)
            mod = self.address_to_module(rip)
            ret = None
            rsp = self.threads[0].get("rsp")
            if rsp:  # first stack qword often a return address into the caller
                raw = self.read(rsp, 8)
                if raw and len(raw) == 8:
                    ra = struct.unpack("<Q", raw)[0]
                    rm = self.address_to_module(ra)
                    ret = {"value": hex(ra), "module": rm[0] if rm else None,
                           "offset": hex(rm[1]) if rm else None}
            crash = {"rip": hex(rip),
                     "rip_module": mod[0] if mod else None,
                     "rip_offset": hex(mod[1]) if mod else None,
                     "stack_return": ret}
        return {
            "available": True, "machine": self.machine,
            "load_segments": len(self.loads), "mapped_modules": len(self.modules()),
            "threads": [{k: hex(v) for k, v in t.items()} for t in self.threads],
            "crash": crash,
            "modules": [{"path": m["path"], "start": hex(m["start"]), "end": hex(m["end"])}
                        for m in self.modules()],
            "note": "ELF core triage — resolve an address with address_to_module, "
                    "pull bytes with read(), find material with search() "
                    "(pair with find_aes_keys over a dumped region).",
        }

    def close(self):
        try:
            self._fh.close()
        except Exception:
            pass


def core_triage(path: str) -> dict:
    """Parse an ELF core dump and return its triage summary."""
    if not Path(path).exists():
        return {"available": True, "error": f"file not found: {path}"}
    try:
        c = CoreDump(path)
    except ValueError as exc:
        return {"available": True, "error": str(exc)}
    try:
        return c.triage()
    finally:
        c.close()
