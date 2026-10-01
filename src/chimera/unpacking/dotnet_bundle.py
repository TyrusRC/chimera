"""Extract the files from a .NET single-file (self-contained) application.

`dotnet publish -p:PublishSingleFile=true` bundles the managed assembly, the
whole CoreCLR runtime, every framework DLL and the `.deps.json` /
`.runtimeconfig.json` into ONE native executable: a small apphost bootstrapper
followed by the bundle appended as an overlay. On disk it looks like a plain
PE/ELF/Mach-O, so `analyze` would hand ~100MB of CoreCLR host to Ghidra and
never reach the app's managed assembly — the .NET analogue of the nexe / SEA /
PyInstaller dead ends that `node_extract` / `pyextract` already handle.

The bundle is located by a fixed 16-byte signature placed in the host; the
8 little-endian bytes immediately before it are the offset to the bundle
manifest header (Microsoft.NET.HostModel.Bundle). The header is:

    uint32 MajorVersion, uint32 MinorVersion, int32 FileCount, string BundleID
    (MajorVersion >= 2:) int64 DepsJson{Offset,Size}, int64 RuntimeConfig{Offset,Size}, uint64 Flags

followed by FileCount entries:

    int64 Offset, int64 Size, int64 CompressedSize, byte Type, string RelativePath

`CompressedSize != 0` means the file body is raw-DEFLATE compressed (the
single-file compression option, header version >= 6). Strings are 7-bit
length-prefixed UTF-8. This carves every file back out so the managed
assembly can go straight to ILSpy / `analyze`.

Pure-Python, read-only — never executes the target. Format-agnostic: it scans
the raw bytes, so a PE, ELF or Mach-O single-file app all work.
"""
from __future__ import annotations

import logging
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# Microsoft.NET.HostModel.Bundle.BundleManifest.BundleSignature — a fixed
# 16-byte marker embedded in the apphost; the int64 right before it is the
# offset to the bundle header.
BUNDLE_SIGNATURE = bytes([
    0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38,
    0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
])

# FileType enum (Microsoft.NET.HostModel.Bundle.FileType).
_FILE_TYPES = {
    0: "Unknown",
    1: "Assembly",
    2: "NativeBinary",
    3: "DepsJson",
    4: "RuntimeConfigJson",
    5: "Symbols",
}


@dataclass
class BundleEntry:
    offset: int
    size: int
    compressed_size: int
    type: str
    path: str

    @property
    def compressed(self) -> bool:
        return self.compressed_size != 0

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "type": self.type,
            "size": self.size,
            "compressed_size": self.compressed_size,
            "offset": self.offset,
        }


@dataclass
class DotnetBundleResult:
    ok: bool
    kind: str = "dotnet-single-file"
    error: str | None = None
    bundle_id: str | None = None
    major_version: int = 0
    minor_version: int = 0
    file_count: int = 0
    entries: list[BundleEntry] = field(default_factory=list)
    out_dir: str | None = None
    main_assembly: str | None = None
    deps_json: str | None = None
    extracted: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "kind": self.kind,
            "error": self.error,
            "bundle_id": self.bundle_id,
            "bundle_version": f"{self.major_version}.{self.minor_version}",
            "file_count": self.file_count,
            "out_dir": self.out_dir,
            "main_assembly": self.main_assembly,
            "deps_json": self.deps_json,
            "extracted_count": len(self.extracted),
            "entries": [e.to_dict() for e in self.entries],
        }


def _read_7bit_string(data: bytes, pos: int) -> tuple[str, int]:
    """Read a .NET 7-bit length-prefixed UTF-8 string; return (value, new_pos)."""
    length = 0
    shift = 0
    while True:
        b = data[pos]
        pos += 1
        length |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return data[pos:pos + length].decode("utf-8", "replace"), pos + length


def find_bundle_header(data: bytes) -> int | None:
    """Return the file offset of the bundle manifest header, or None."""
    sig = data.find(BUNDLE_SIGNATURE)
    if sig < 8:
        return None
    (header_offset,) = struct.unpack_from("<q", data, sig - 8)
    if 0 < header_offset < len(data):
        return header_offset
    return None


def is_single_file_bundle(target: str | Path | bytes) -> bool:
    """Cheap check: does this file/bytes carry a .NET single-file bundle?"""
    try:
        if isinstance(target, (bytes, bytearray)):
            data = bytes(target)
        else:
            data = Path(target).read_bytes()
    except OSError:
        return False
    return find_bundle_header(data) is not None


def parse_manifest(data: bytes) -> tuple[dict, list[BundleEntry]]:
    """Parse the bundle header + file entries. Raises ValueError if not found."""
    header_offset = find_bundle_header(data)
    if header_offset is None:
        raise ValueError("no .NET single-file bundle signature found")

    pos = header_offset
    major, minor = struct.unpack_from("<II", data, pos)
    pos += 8
    (count,) = struct.unpack_from("<i", data, pos)
    pos += 4
    bundle_id, pos = _read_7bit_string(data, pos)

    # Header version >= 2 carries deps.json / runtimeconfig.json locations + flags.
    if major >= 2:
        pos += 32  # (deps off,size) + (runtimeconfig off,size), four int64
        pos += 8   # uint64 flags

    entries: list[BundleEntry] = []
    for _ in range(count):
        offset, size, csize = struct.unpack_from("<qqq", data, pos)
        pos += 24
        ftype = data[pos]
        pos += 1
        rel_path, pos = _read_7bit_string(data, pos)
        entries.append(BundleEntry(
            offset=offset,
            size=size,
            compressed_size=csize,
            type=_FILE_TYPES.get(ftype, f"Unknown({ftype})"),
            path=rel_path,
        ))

    header = {"major": major, "minor": minor, "bundle_id": bundle_id, "count": count}
    return header, entries


def _entry_bytes(data: bytes, entry: BundleEntry) -> bytes:
    raw = data[entry.offset:entry.offset + (entry.compressed_size or entry.size)]
    if entry.compressed:
        try:
            return zlib.decompress(raw, -15)  # raw DEFLATE (single-file compression)
        except zlib.error as exc:
            logger.warning("deflate failed for %s: %s — writing raw", entry.path, exc)
            return data[entry.offset:entry.offset + entry.size]
    return raw


def extract_bundle(path: str | Path, out_dir: str | Path | None = None) -> DotnetBundleResult:
    """Extract every file from a .NET single-file app into `out_dir`.

    Returns a result pointing at the recovered main managed assembly (the
    `Assembly` whose name matches the host, else the first non-framework one)
    — feed that to `chimera analyze` / ILSpy.
    """
    src = Path(path)
    try:
        data = src.read_bytes()
    except OSError as exc:
        return DotnetBundleResult(ok=False, error=f"cannot read {src}: {exc}")

    try:
        header, entries = parse_manifest(data)
    except (ValueError, struct.error, IndexError) as exc:
        return DotnetBundleResult(ok=False, error=str(exc))

    out = Path(out_dir) if out_dir else src.with_name(f"{src.stem}_bundle")
    out.mkdir(parents=True, exist_ok=True)

    extracted: list[str] = []
    deps_json: str | None = None
    for entry in entries:
        # RelativePath can contain subdirs (locale satellites); keep the tree
        # but refuse traversal outside out_dir.
        dest = (out / entry.path).resolve()
        try:
            dest.relative_to(out.resolve())
        except ValueError:
            logger.warning("skipping path traversal entry: %s", entry.path)
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            dest.write_bytes(_entry_bytes(data, entry))
        except OSError as exc:
            logger.warning("write failed for %s: %s", entry.path, exc)
            continue
        extracted.append(entry.path)
        if entry.type == "DepsJson":
            deps_json = str(dest)

    main_assembly = _pick_main_assembly(src.stem, entries, out)

    return DotnetBundleResult(
        ok=True,
        bundle_id=header["bundle_id"],
        major_version=header["major"],
        minor_version=header["minor"],
        file_count=header["count"],
        entries=entries,
        out_dir=str(out),
        main_assembly=main_assembly,
        deps_json=deps_json,
        extracted=extracted,
    )


def _pick_main_assembly(host_stem: str, entries: list[BundleEntry], out: Path) -> str | None:
    """The app's managed DLL: prefer <hostname>.dll, else the first non-framework
    Assembly (skip System.*/Microsoft.*/satellite resources)."""
    assemblies = [e for e in entries if e.type == "Assembly"]
    host_dll = f"{host_stem}.dll".lower()
    for e in assemblies:
        if Path(e.path).name.lower() == host_dll:
            return str(out / e.path)

    def _is_framework(p: str) -> bool:
        name = Path(p).name.lower()
        return (name.startswith(("system.", "microsoft.", "netstandard"))
                or name in ("mscorlib.dll", "windowsbase.dll", "accessibility.dll")
                or name.endswith(".resources.dll"))

    for e in assemblies:
        if not _is_framework(e.path):
            return str(out / e.path)
    return str(out / assemblies[0].path) if assemblies else None
