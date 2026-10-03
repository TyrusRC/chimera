"""Carve the embedded web frontend out of a Tauri (Rust) desktop app.

Tauri bundles its UI (HTML/JS/CSS/images) *into the Rust executable* via the
``tauri::include_dir!``/``EmbeddedAssets`` mechanism — a different packaging from
Electron's `app.asar` (a separate archive) or a Node SEA (an appended blob). On an
ELF build the assets live as a table in ``.data.rel.ro``: an array of 32-byte
entries ``[key_ptr, key_len, blob_ptr, blob_len]`` where the two pointers are
``R_X86_64_RELATIVE`` relocations (so the real target VA is the reloc addend). Each
key is a ``/path`` string; each blob is the asset body, usually **brotli**
compressed (sometimes zstd or stored). This module finds that table with no
hardcoded offsets — it scans ``.data.rel.ro`` for the entry shape, resolves the
relocations, and decompresses each asset.

Read-only, pure-Python; it never executes the target. Brotli/zstd decompression is
best-effort and degrades to the raw blob if the codec (or its Python module) is
missing.

**Important caveat the result flags:** some Tauri apps do NOT ship their real logic
in these static assets — they embed their own V8/JS engine (rusty_v8) and
*runtime-decrypt* the script into the isolate. When the carved ``index.html``
references scripts that are not among the extracted assets, or the binary links
rusty_v8, the frontend you get here is only a shell and the logic must be recovered
dynamically (run the isolate / scrape the decrypted script). The result says so.
"""
from __future__ import annotations

import logging
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# Entry = key_ptr(8) key_len(8) blob_ptr(8) blob_len(8). Keys are short "/paths".
_MAX_KEY_LEN = 512
_MAX_BLOB_LEN = 64 * 1024 * 1024
# Sections that can hold the relocated EmbeddedAssets table (data.rel.ro first).
_ASSET_SECTIONS = (".data.rel.ro", ".data", ".rodata")
_R_X86_64_RELATIVE = 8
_TAURI_VER_RE = re.compile(rb"tauri-(\d+\.\d+\.\d+)")
_RUSTY_V8_RE = re.compile(rb"rusty_v8-(\d+\.\d+\.\d+)")
# A local <script src="..."> / module import referencing a path (to cross-check
# against the carved assets — a referenced-but-absent script = runtime-loaded).
_SCRIPT_SRC_RE = re.compile(rb"""<script[^>]*\bsrc\s*=\s*["']([^"']+)["']""", re.I)


@dataclass
class TauriAsset:
    name: str          # the "/path" key
    blob_offset: int   # file offset of the (compressed) blob
    blob_size: int     # stored (compressed) size
    codec: str         # "brotli" | "zstd" | "stored" | "undecoded"
    out_size: int      # decompressed size (== blob_size when stored/undecoded)
    out_path: str = ""  # where it was written (if out_dir given)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "blob_offset": self.blob_offset,
            "blob_size": self.blob_size,
            "codec": self.codec,
            "out_size": self.out_size,
            "out_path": self.out_path,
        }


@dataclass
class TauriExtractResult:
    ok: bool
    is_tauri: bool = False
    tauri_version: str | None = None
    embedded_v8: str | None = None   # e.g. "rusty_v8-0.32.1" if present, else None
    assets: list[TauriAsset] = field(default_factory=list)
    out_dir: str = ""
    signals: list[str] = field(default_factory=list)
    note: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "is_tauri": self.is_tauri,
            "tauri_version": self.tauri_version,
            "embedded_v8": self.embedded_v8,
            "assets": [a.to_dict() for a in self.assets],
            "out_dir": self.out_dir,
            "signals": self.signals,
            "note": self.note,
            "error": self.error,
        }


def detect_tauri_binary(data: bytes) -> bool:
    """True if the bytes look like a Tauri app (any OS)."""
    return (
        b"__TAURI_INTERNALS__" in data
        or b"__TAURI__" in data
        or _TAURI_VER_RE.search(data) is not None
        or (b"wry-" in data and b"tao-" in data)
    )


# --------------------------------------------------------------------------- #
# Minimal ELF64 section + RELATIVE-reloc parsing (self-contained, like nodejs.py)
# --------------------------------------------------------------------------- #
@dataclass
class _Elf:
    sections: list[tuple[str, int, int, int, int]]  # name, type, addr, off, size
    relocs: dict[int, int]                            # loc_va -> addend (target va)


def _parse_elf64(data: bytes) -> _Elf | None:
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2:  # EI_CLASS=ELFCLASS64
        return None
    shoff = struct.unpack_from("<Q", data, 0x28)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    if shoff == 0 or shnum == 0 or shoff + shnum * shentsize > len(data):
        return None
    raw = []
    for i in range(shnum):
        base = shoff + i * shentsize
        name, stype, _flags, addr, off, size = struct.unpack_from("<IIQQQQ", data, base)
        raw.append((name, stype, addr, off, size))
    strtab_off = raw[shstrndx][3]

    def _nm(n: int) -> str:
        end = data.index(b"\0", strtab_off + n)
        return data[strtab_off + n : end].decode("latin1")

    sections = [(_nm(n), t, a, o, s) for (n, t, a, o, s) in raw]

    # Collect R_X86_64_RELATIVE relocs from every SHT_RELA section (type 4).
    relocs: dict[int, int] = {}
    for _name, stype, _addr, off, size in sections:
        if stype != 4:  # SHT_RELA
            continue
        for i in range(size // 24):
            loc, info, add = struct.unpack_from("<QQq", data, off + i * 24)
            if info & 0xFFFFFFFF == _R_X86_64_RELATIVE:
                relocs[loc] = add
    return _Elf(sections=sections, relocs=relocs)


def _va2off(elf: _Elf, va: int) -> int | None:
    for _name, stype, addr, off, size in elf.sections:
        if addr and stype != 8 and addr <= va < addr + size:  # skip SHT_NOBITS(.bss)
            return off + va - addr
    return None


def _scan_asset_table(data: bytes, elf: _Elf) -> list[TauriAsset]:
    """Find EmbeddedAssets entries in the relocated data sections."""
    assets: list[TauriAsset] = []
    seen: set[int] = set()
    for name, _stype, addr, _off, size in elf.sections:
        if name not in _ASSET_SECTIONS or not addr:
            continue
        for loc in range(addr, addr + size - 32, 8):
            if loc in seen or loc not in elf.relocs:
                continue
            entry_off = _va2off(elf, loc)
            if entry_off is None:
                continue
            key_ptr = elf.relocs[loc]
            key_off = _va2off(elf, key_ptr)
            if key_off is None:
                continue
            key_len = struct.unpack_from("<Q", data, entry_off + 8)[0]
            if not (0 < key_len < _MAX_KEY_LEN):
                continue
            key = data[key_off : key_off + key_len]
            # EmbeddedAssets keys are URL-ish "/path" byte strings.
            if not (key[:1] == b"/" and all(32 <= c < 127 for c in key)):
                continue
            if (loc + 16) not in elf.relocs:
                continue
            blob_ptr = elf.relocs[loc + 16]
            blob_off = _va2off(elf, blob_ptr)
            if blob_off is None:
                continue
            blob_len = struct.unpack_from("<Q", data, entry_off + 24)[0]
            if not (0 < blob_len <= _MAX_BLOB_LEN) or blob_off + blob_len > len(data):
                continue
            seen.add(loc)
            assets.append(
                TauriAsset(
                    name=key.decode("latin1"),
                    blob_offset=blob_off,
                    blob_size=blob_len,
                    codec="",
                    out_size=0,
                )
            )
    assets.sort(key=lambda a: a.name)
    return assets


def _decompress(blob: bytes) -> tuple[bytes, str]:
    """Return (decompressed_bytes, codec). Falls back to the raw blob."""
    try:
        import brotli  # type: ignore

        return brotli.decompress(blob), "brotli"
    except Exception:
        pass
    try:
        import zstandard  # type: ignore

        return zstandard.ZstdDecompressor().decompress(blob), "zstd"
    except Exception:
        pass
    # Stored/identity assets (small HTML/JSON) are often not compressed at all.
    if blob[:1] in (b"<", b"{", b"/") and all(
        c == 9 or c == 10 or c == 13 or 32 <= c < 127 for c in blob[:64]
    ):
        return blob, "stored"
    return blob, "undecoded"


def carve_embedded_assets(data: bytes, out_dir: Path | None = None) -> list[TauriAsset]:
    """Carve + decompress the EmbeddedAssets table from ELF Tauri bytes."""
    elf = _parse_elf64(data)
    if elf is None:
        return []
    assets = _scan_asset_table(data, elf)
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
    for a in assets:
        blob = data[a.blob_offset : a.blob_offset + a.blob_size]
        decoded, codec = _decompress(blob)
        a.codec = codec
        a.out_size = len(decoded)
        if out_dir is not None:
            # Flatten "/a/b.png" -> "a_b.png"; guard traversal.
            safe = a.name.strip("/").replace("/", "_").replace("..", "_") or "index"
            dest = out_dir / safe
            dest.write_bytes(decoded)
            a.out_path = str(dest)
    return assets


def _runtime_logic_note(data: bytes, assets: list[TauriAsset], out_dir: Path | None) -> str:
    """Flag when the real logic is likely NOT in the static assets."""
    notes: list[str] = []
    if _RUSTY_V8_RE.search(data) or b"rusty_v8" in data:
        notes.append(
            "binary statically links rusty_v8 — logic may run in an embedded V8 "
            "isolate and be runtime-decrypted (not in these static assets)"
        )
    # Cross-check: does index.html reference a local script that we did NOT carve?
    names = {a.name.lstrip("/") for a in assets}
    html = b""
    if out_dir is not None:
        for a in assets:
            if a.name.endswith(".html") and a.out_path:
                try:
                    html = Path(a.out_path).read_bytes()
                except OSError:
                    pass
                break
    for m in _SCRIPT_SRC_RE.finditer(html):
        src = m.group(1).decode("latin1").lstrip("./").lstrip("/")
        if src and "://" not in src and src not in names:
            notes.append(f"index.html references script '{src}' not among carved assets")
    return "; ".join(notes)


def extract_tauri(path: str | Path, out_dir: str | Path | None = None) -> TauriExtractResult:
    """Top-level entry: detect Tauri, carve its embedded web assets, write them out.

    Read-only; never executes the target.
    """
    path = Path(path)
    try:
        data = path.read_bytes()
    except OSError as exc:
        return TauriExtractResult(ok=False, error=f"cannot read {path}: {exc}")

    is_tauri = detect_tauri_binary(data)
    signals: list[str] = []
    if b"__TAURI_INTERNALS__" in data:
        signals.append("__TAURI_INTERNALS__")
    tv = _TAURI_VER_RE.search(data)
    if tv:
        signals.append(f"tauri-{tv.group(1).decode()}")
    rv = _RUSTY_V8_RE.search(data)
    embedded_v8 = f"rusty_v8-{rv.group(1).decode()}" if rv else (
        "rusty_v8" if b"rusty_v8" in data else None
    )
    if embedded_v8:
        signals.append(embedded_v8)

    if not is_tauri:
        return TauriExtractResult(
            ok=False, is_tauri=False, signals=signals,
            error="not a Tauri binary (no __TAURI__ / tauri-<ver> / wry+tao markers)",
        )

    is_elf = data[:4] == b"\x7fELF"
    out = Path(out_dir) if out_dir else path.parent / f"{path.stem}_tauri_assets"
    assets: list[TauriAsset] = []
    if is_elf:
        assets = carve_embedded_assets(data, out)
    note = _runtime_logic_note(data, assets, out if assets else None)
    if not assets and not is_elf:
        note = (note + "; " if note else "") + (
            "asset carving currently supports ELF; this is a Tauri "
            f"{'PE' if data[:2] == b'MZ' else 'Mach-O/other'} — detection only"
        )
    elif not assets and is_elf:
        note = (note + "; " if note else "") + (
            "no EmbeddedAssets table found (frontend may be externally bundled "
            "or the assets are packed differently)"
        )
    return TauriExtractResult(
        ok=bool(assets) or is_tauri,
        is_tauri=True,
        tauri_version=tv.group(1).decode() if tv else None,
        embedded_v8=embedded_v8,
        assets=assets,
        out_dir=str(out) if assets else "",
        signals=signals,
        note=note,
    )
