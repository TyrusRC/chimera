"""Pure-Python WebAssembly binary parser — section/import/export/memory recon.

Reads the module structure directly from the bytes: the version, the section
table, the import and export tables, the memory limits, how many functions are
defined vs imported, the data-segment count, and any custom sections (the
``name`` symbol table and the ``producers`` toolchain record). No external tool
and no third-party library — this is the cheap recon that runs before wabt /
binaryen are reached.

Never raises on a malformed or truncated module: an analyst dropping a corrupt
``.wasm`` expects best-effort triage, the same contract the ELF/PE parsers hold.
A short read just stops the walk and returns what was recovered so far.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

WASM_MAGIC = b"\x00asm"

# Section ids (WebAssembly core spec §5.5.2).
_SECTION_NAMES = {
    0: "custom", 1: "type", 2: "import", 3: "function", 4: "table",
    5: "memory", 6: "global", 7: "export", 8: "start", 9: "element",
    10: "code", 11: "data", 12: "datacount",
}
# Import/export external kinds.
_KINDS = {0: "func", 1: "table", 2: "memory", 3: "global"}


@dataclass
class WasmImport:
    module: str
    field: str
    kind: str


@dataclass
class WasmExport:
    name: str
    kind: str
    index: int


@dataclass
class WasmSection:
    id: int
    name: str              # "type"/"import"/…; for custom, the section's own name
    size: int              # payload length in bytes


@dataclass
class WasmModule:
    version: int = 1
    sections: list[WasmSection] = field(default_factory=list)
    imports: list[WasmImport] = field(default_factory=list)
    exports: list[WasmExport] = field(default_factory=list)
    memory_min_pages: int | None = None
    memory_max_pages: int | None = None
    imported_func_count: int = 0
    defined_func_count: int = 0
    data_segment_count: int = 0
    custom_sections: list[str] = field(default_factory=list)
    #: Function names recovered from the "name" section (index -> name). Empty on
    #: a stripped (`-s -w`) build — the decisive Go-WASM "despises humanity" tell.
    function_names: dict[int, str] = field(default_factory=dict)
    producers: str | None = None       # raw text of the "producers" custom section
    truncated: bool = False            # the walk stopped early on a short read

    @property
    def total_func_count(self) -> int:
        return self.imported_func_count + self.defined_func_count

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "sections": [{"id": s.id, "name": s.name, "size": s.size}
                         for s in self.sections],
            "imports": [{"module": i.module, "field": i.field, "kind": i.kind}
                        for i in self.imports],
            "exports": [{"name": e.name, "kind": e.kind, "index": e.index}
                        for e in self.exports],
            "memory_min_pages": self.memory_min_pages,
            "memory_max_pages": self.memory_max_pages,
            "imported_func_count": self.imported_func_count,
            "defined_func_count": self.defined_func_count,
            "total_func_count": self.total_func_count,
            "data_segment_count": self.data_segment_count,
            "custom_sections": self.custom_sections,
            "function_names": self.function_names,
            "producers": self.producers,
            "truncated": self.truncated,
        }


class _Reader:
    """Byte cursor with LEB128 decoding. Raises _Short on an out-of-bounds read."""

    class _Short(Exception):
        pass

    def __init__(self, data: bytes, pos: int = 0):
        self.data = data
        self.pos = pos

    def byte(self) -> int:
        if self.pos >= len(self.data):
            raise self._Short
        b = self.data[self.pos]
        self.pos += 1
        return b

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise self._Short
        b = self.data[self.pos:self.pos + n]
        self.pos += n
        return b

    def uleb(self) -> int:
        result = 0
        shift = 0
        while True:
            b = self.byte()
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                return result
            shift += 7
            if shift > 63:                       # malformed; stop rather than loop
                raise self._Short

    def name(self) -> str:
        n = self.uleb()
        return self.take(n).decode("utf-8", "replace")


def is_wasm(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == WASM_MAGIC
    except OSError:
        return False


def parse_wasm(path: Path) -> WasmModule:
    """Parse the section structure of a .wasm module. Best-effort, never raises."""
    path = Path(path)
    data = path.read_bytes()
    mod = WasmModule()
    if data[:4] != WASM_MAGIC:
        return mod
    if len(data) >= 8:
        mod.version = int.from_bytes(data[4:8], "little")

    r = _Reader(data, 8)
    try:
        while r.pos < len(data):
            sec_id = r.byte()
            sec_size = r.uleb()
            payload = r.take(sec_size)
            name = _SECTION_NAMES.get(sec_id, f"unknown({sec_id})")
            if sec_id == 0:                       # custom: payload starts with its name
                cr = _Reader(payload)
                try:
                    cname = cr.name()
                except _Reader._Short:
                    cname = "<custom>"
                name = cname
                mod.custom_sections.append(cname)
                _parse_custom(mod, cname, payload[cr.pos:])
            mod.sections.append(WasmSection(id=sec_id, name=name, size=sec_size))
            _parse_known_section(mod, sec_id, payload)
    except _Reader._Short:
        mod.truncated = True
    return mod


def _parse_known_section(mod: WasmModule, sec_id: int, payload: bytes) -> None:
    """Decode the handful of sections recon needs. Isolated so a malformed one
    only drops its own data (its _Short is swallowed), not the whole walk."""
    r = _Reader(payload)
    try:
        if sec_id == 2:                           # import
            for _ in range(r.uleb()):
                module = r.name()
                fld = r.name()
                kind = _KINDS.get(r.byte(), "other")
                mod.imports.append(WasmImport(module, fld, kind))
                if kind == "func":
                    mod.imported_func_count += 1
                    r.uleb()                      # type index
                elif kind == "table":
                    r.byte(); _limits(r)          # elemtype, limits
                elif kind == "memory":
                    _limits(r)
                elif kind == "global":
                    r.byte(); r.byte()            # valtype, mutability
        elif sec_id == 3:                         # function (defined funcs)
            mod.defined_func_count = r.uleb()
        elif sec_id == 5:                         # memory
            if r.uleb() >= 1:
                lo, hi = _limits(r)
                mod.memory_min_pages, mod.memory_max_pages = lo, hi
        elif sec_id == 7:                         # export
            for _ in range(r.uleb()):
                nm = r.name()
                kind = _KINDS.get(r.byte(), "other")
                idx = r.uleb()
                mod.exports.append(WasmExport(nm, kind, idx))
        elif sec_id in (11, 12):                  # data / datacount
            mod.data_segment_count = r.uleb()
    except _Reader._Short:
        return


def _limits(r: _Reader) -> tuple[int, int | None]:
    flags = r.byte()
    lo = r.uleb()
    hi = r.uleb() if (flags & 0x1) else None
    return lo, hi


def _parse_custom(mod: WasmModule, cname: str, body: bytes) -> None:
    if cname == "producers":
        mod.producers = body.decode("utf-8", "replace")
    elif cname == "name":
        _parse_name_section(mod, body)


def _parse_name_section(mod: WasmModule, body: bytes) -> None:
    """Decode the function-name subsection (subsection id 1) of the name section."""
    r = _Reader(body)
    try:
        while r.pos < len(body):
            sub_id = r.byte()
            sub_len = r.uleb()
            sub = r.take(sub_len)
            if sub_id == 1:                       # function names
                sr = _Reader(sub)
                for _ in range(sr.uleb()):
                    idx = sr.uleb()
                    mod.function_names[idx] = sr.name()
    except _Reader._Short:
        return
