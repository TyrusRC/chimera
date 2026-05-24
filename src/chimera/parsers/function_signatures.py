"""FLIRT-equivalent function signature matcher.

FLIRT (IDA's "Fast Library Identification and Recognition Technology") is
proprietary. This module implements a comparable but simpler scheme that
is good enough to rename a large fraction of statically-linked library
functions in PE / ELF / Mach-O binaries: stripped libc, libssl, zlib,
curl, and friends.

A signature is a masked-byte prefix of a known function. We store::

    {
      "name": "memcpy",
      "lib":  "libc",
      "size": 64,                 # source function size (bytes)
      "bytes_hex": "488b...",     # first N opcode bytes
      "mask_hex":  "ffff00...",   # 0xff = compare, 0x00 = wildcard
      "arch":    "x86_64",
      "format":  "elf",
      "crc16_tail": 0xa3f1        # optional secondary check on bytes [32, size]
    }

At match time we walk the model's function list, pull each function's
first-N bytes from the binary file (no live r2 dependency — we use
`pefile` / `pyelftools` to resolve the section offset), then compare
against every signature whose (arch, format) is compatible.

A function counts as "library" when the masked match exactly hits the
signature byte-stream. The optional `crc16_tail` is used to disambiguate
prefixes that are byte-identical at the head (variants of memset/memcpy).
"""

from __future__ import annotations

import json
import logging
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

logger = logging.getLogger(__name__)

# A signature is small (~32 byte prefix). Bigger windows risk false negatives
# on optimisation variants without buying much specificity — most libc fns
# diverge from each other within the first 16 bytes.
SIG_BYTES = 32

DEFAULT_SIG_DIR = Path(__file__).resolve().parent.parent / "data" / "sigs"


@dataclass
class Signature:
    name: str
    lib: str
    size: int
    bytes_: bytes
    mask: bytes
    arch: str
    format: str
    crc16_tail: Optional[int] = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Signature":
        return cls(
            name=d["name"],
            lib=d["lib"],
            size=int(d.get("size", 0)),
            bytes_=bytes.fromhex(d["bytes_hex"]),
            mask=bytes.fromhex(d["mask_hex"]),
            arch=d.get("arch", "x86_64"),
            format=d.get("format", "elf"),
            crc16_tail=d.get("crc16_tail"),
        )

    def matches(self, candidate: bytes) -> bool:
        """True iff candidate[:N] equals self.bytes_ where mask is 0xff."""
        n = min(len(self.bytes_), len(self.mask), len(candidate))
        for i in range(n):
            if self.mask[i] and (candidate[i] & self.mask[i]) != (self.bytes_[i] & self.mask[i]):
                return False
        return True


@dataclass
class SignatureDB:
    by_arch_fmt: dict[tuple[str, str], list[Signature]] = field(default_factory=dict)

    def add(self, sig: Signature) -> None:
        self.by_arch_fmt.setdefault((sig.arch, sig.format), []).append(sig)

    def lookup(self, arch: str, fmt: str) -> list[Signature]:
        return self.by_arch_fmt.get((arch, fmt), [])

    def total(self) -> int:
        return sum(len(v) for v in self.by_arch_fmt.values())


def load_signature_db(directory: Path | None = None) -> SignatureDB:
    """Read every `*.json` file in the signature directory into a SignatureDB.

    Missing directory / missing files are not an error — they just mean
    "no signatures bundled", and the matcher will no-op. Malformed entries
    are logged and skipped so one bad signature doesn't poison the whole
    pack.
    """
    db = SignatureDB()
    base = Path(directory) if directory else DEFAULT_SIG_DIR
    if not base.exists():
        return db
    for fp in sorted(base.glob("*.json")):
        try:
            blob = json.loads(fp.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("signature pack %s unreadable: %s", fp, exc)
            continue
        for entry in blob.get("signatures", []):
            try:
                db.add(Signature.from_dict(entry))
            except (KeyError, ValueError) as exc:
                logger.warning("malformed signature in %s: %s", fp, exc)
    logger.info("loaded %d signatures from %s", db.total(), base)
    return db


# ---------------------------------------------------------------------------
# Byte extraction — we pull the function's first SIG_BYTES from the binary
# using format-specific section lookup. This sidesteps a live r2 pipe, which
# would be a heavy dependency for what is essentially "seek + read".
# ---------------------------------------------------------------------------


def _extract_bytes_pe(binary_path: Path, virtual_address: int, length: int) -> Optional[bytes]:
    """Read `length` bytes at PE virtual_address by walking section headers."""
    try:
        import pefile
        pe = pefile.PE(str(binary_path), fast_load=True)
    except Exception as exc:
        logger.debug("pefile open failed for %s: %s", binary_path, exc)
        return None
    try:
        image_base = pe.OPTIONAL_HEADER.ImageBase
        rva = virtual_address - image_base
        return pe.get_data(rva, length)
    except Exception:
        return None
    finally:
        pe.close()


def _extract_bytes_elf(binary_path: Path, virtual_address: int, length: int) -> Optional[bytes]:
    """Walk ELF program headers to map virtual_address to a file offset."""
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        return None
    try:
        with open(binary_path, "rb") as fh:
            elf = ELFFile(fh)
            for seg in elf.iter_segments():
                if seg["p_type"] != "PT_LOAD":
                    continue
                vstart = seg["p_vaddr"]
                vsize = seg["p_filesz"]
                if vstart <= virtual_address < vstart + vsize:
                    file_offset = seg["p_offset"] + (virtual_address - vstart)
                    fh.seek(file_offset)
                    return fh.read(length)
    except Exception as exc:
        logger.debug("ELF read failed for %s @ 0x%x: %s", binary_path, virtual_address, exc)
    return None


def _extract_bytes_macho(binary_path: Path, virtual_address: int, length: int) -> Optional[bytes]:
    """Best-effort Mach-O extractor; relies on LC_SEGMENT_64 ranges."""
    try:
        with open(binary_path, "rb") as fh:
            data = fh.read()
        # Skip the FAT/universal wrapper if present — the per-arch slice is
        # the only thing the model's addresses point into.
        if data[:4] == b"\xca\xfe\xba\xbe":
            # Header reads first slice for simplicity. Multi-arch binaries
            # need a more involved walker; treat them as unsupported for now.
            return None
        magic = data[:4]
        if magic not in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
            return None
        # Parse just enough to find the segments. 64-bit only.
        # mach_header_64 = magic(4) cputype(4) cpusubtype(4) filetype(4)
        #                  ncmds(4) sizeofcmds(4) flags(4) reserved(4) = 32
        ncmds, = struct.unpack_from("<I", data, 16)
        offset = 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", data, offset)
            if cmd == 0x19:  # LC_SEGMENT_64
                # segname(16) vmaddr(8) vmsize(8) fileoff(8) filesize(8) ...
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                    "<QQQQ", data, offset + 8 + 16,
                )
                if vmaddr <= virtual_address < vmaddr + filesize:
                    file_off = fileoff + (virtual_address - vmaddr)
                    return data[file_off:file_off + length]
            offset += cmdsize
    except Exception as exc:
        logger.debug("Mach-O read failed for %s: %s", binary_path, exc)
    return None


def extract_function_bytes(
    binary_path: Path, address: str | int, fmt: str, length: int = SIG_BYTES,
) -> Optional[bytes]:
    """Dispatch byte extraction by binary format.

    `fmt` is the lowercase `BinaryFormat.value` from the model. Anything we
    don't recognise returns None and the caller silently skips that function.
    """
    if isinstance(address, str):
        try:
            address = int(address, 16)
        except ValueError:
            return None
    fmt = (fmt or "").lower()
    if fmt in {"pe32", "pe64", "pe", "dotnet_pe"}:
        return _extract_bytes_pe(binary_path, address, length)
    if fmt == "elf":
        return _extract_bytes_elf(binary_path, address, length)
    if fmt in {"macho", "dylib", "fat"}:
        return _extract_bytes_macho(binary_path, address, length)
    return None


# ---------------------------------------------------------------------------
# Matcher — the entry point pipelines call after the model's functions are
# populated by r2 + Ghidra.
# ---------------------------------------------------------------------------


def _arch_for_model(model, binary_path: Optional[Path] = None) -> str:
    """Map BinaryInfo.arch to the signature DB's arch key.

    BinaryInfo's heuristic detection sometimes returns "unknown" (notably
    on bare shared libraries that don't look like a mobile artifact). In
    that case we fall back to reading the ELF machine field directly.
    """
    raw = (model.binary.arch.value if model.binary.arch else "").lower()
    mapped = {
        "x86_64": "x86_64", "amd64": "x86_64",
        "x86": "x86", "i386": "x86",
        "aarch64": "aarch64", "arm64": "aarch64", "arm64e": "aarch64",
        "arm32": "arm",
    }.get(raw)
    if mapped:
        return mapped
    if binary_path is None:
        return raw or "unknown"
    return _arch_from_binary(binary_path) or raw or "unknown"


def _arch_from_binary(binary_path: Path) -> Optional[str]:
    """Sniff arch directly from the binary; used when the model is unsure."""
    try:
        from elftools.elf.elffile import ELFFile
        with open(binary_path, "rb") as fh:
            elf = ELFFile(fh)
            mach = elf.header["e_machine"]
            return {
                "EM_X86_64": "x86_64",
                "EM_386": "x86",
                "EM_AARCH64": "aarch64",
                "EM_ARM": "arm",
            }.get(mach)
    except Exception:
        return None


def _format_for_model(model) -> str:
    raw = (model.binary.format.value if model.binary.format else "").lower()
    if raw in {"pe32", "pe64", "dotnet_pe", "dll"}:
        return "pe"
    if raw in {"elf", "elf_standalone"}:
        return "elf"
    if raw in {"macho", "dylib", "fat"}:
        return "macho"
    return raw


def match_functions(
    model, binary_path: Path, db: Optional[SignatureDB] = None,
    only_unknown: bool = True,
) -> dict[str, Any]:
    """Walk model.functions and tag library matches in place.

    Returns a stats dict for the pipeline to log.
    `only_unknown` — when True, only rename functions whose name still looks
    like a backend placeholder (FUN_*, sub_*, sym.imp.*) so analyst-renamed
    functions aren't clobbered.
    """
    db = db or load_signature_db()
    arch = _arch_for_model(model, binary_path)
    fmt = _format_for_model(model)
    sigs = db.lookup(arch, fmt)
    if not sigs:
        return {"matched": 0, "scanned": 0, "total_sigs": db.total(), "arch_fmt": f"{arch}/{fmt}"}

    matched = 0
    scanned = 0
    for func in model.functions:
        if only_unknown and not _looks_unnamed(func.name):
            continue
        candidate = extract_function_bytes(binary_path, func.address, fmt, SIG_BYTES)
        if not candidate or len(candidate) < 4:
            continue
        scanned += 1
        for sig in sigs:
            if sig.matches(candidate):
                func.original_name = sig.name
                func.name = sig.name
                func.classification = "library"
                if func.metadata is None:
                    func.metadata = {}
                func.metadata["library_match"] = {
                    "lib": sig.lib, "matched_by": "chimera-sig",
                }
                matched += 1
                break

    logger.info(
        "signature matcher: %d matched / %d scanned (%d sigs, %s/%s)",
        matched, scanned, len(sigs), arch, fmt,
    )
    return {"matched": matched, "scanned": scanned, "total_sigs": len(sigs), "arch_fmt": f"{arch}/{fmt}"}


def _looks_unnamed(name: str) -> bool:
    """Return True for the backend-emitted "unnamed function" patterns."""
    if not name:
        return True
    n = name.lower()
    return (
        n.startswith("fun_")
        or n.startswith("sub_")
        or n.startswith("sym.imp.")
        or n.startswith("loc_")
        or n.startswith("entry")
        or n.startswith("fcn.")
        or n == "main"   # main is often correctly named upstream; safe to skip
    )


# ---------------------------------------------------------------------------
# Helpers for the builder script — exposed so `scripts/build_libfn_sigs.py`
# can reuse the parsing code paths instead of duplicating them.
# ---------------------------------------------------------------------------


def signature_from_bytes(
    name: str, lib: str, prefix: bytes, arch: str, format: str,
    size: int | None = None, mask: bytes | None = None,
) -> Signature:
    """Construct a Signature from raw bytes; default mask is all-0xff."""
    if mask is None:
        mask = b"\xff" * len(prefix)
    return Signature(
        name=name, lib=lib, size=size or len(prefix),
        bytes_=prefix, mask=mask, arch=arch, format=format,
    )


def dump_signature_pack(
    sigs: Iterable[Signature], out_path: Path, pack_name: str,
) -> int:
    """Write a JSON signature pack to disk. Returns the number of entries."""
    entries = [
        {
            "name": s.name, "lib": s.lib, "size": s.size,
            "bytes_hex": s.bytes_.hex(), "mask_hex": s.mask.hex(),
            "arch": s.arch, "format": s.format,
            **({"crc16_tail": s.crc16_tail} if s.crc16_tail is not None else {}),
        }
        for s in sigs
    ]
    payload = {"pack": pack_name, "version": 1, "signatures": entries}
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2))
    return len(entries)
