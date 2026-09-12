"""Carve a UEFI firmware image (OVMF / BIOS / SPI flash) into its modules.

chimera had no concept of firmware: `analyze` mis-sniffs a firmware volume as an
ELF and aborts. Yet a UEFI target (a bootkit, a firmware implant, a boot-stage
CTF like a malicious DXE hidden in a rebuilt OVMF) is triaged by carving its
firmware volumes and listing the FFS modules by GUID + UI-name, then extracting
the suspicious DXE/PEIM as a normal PE/TE to analyze it.

This wraps `uefi_firmware` (the parser behind uefi-firmware-parser): recurse the
FVs, emit one entry per FFS file that carries a PE32/TE image (its GUID, UI-name,
size), and optionally extract those module bytes. The library is an optional
extra (`chimera[firmware]`); without it this returns a clear "not available".
"""
from __future__ import annotations

import re
from pathlib import Path

# _FVH is the EFI_FIRMWARE_VOLUME_HEADER signature (at offset 0x28 of each FV).
_FVH = b"_FVH"
_GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
_VER_RE = re.compile(r"^\d+(\.\d+)*$")


def uefi_available() -> bool:
    try:
        import uefi_firmware  # noqa: F401
        return True
    except Exception:
        return False


def is_uefi_firmware(data: bytes) -> bool:
    """True if the blob looks like a UEFI firmware image (a `_FVH` volume).

    Cheap structural check for the format classifier: the firmware-volume
    signature sits at offset 0x28 of a volume; a flash image may lead with a
    padding/other region, so also accept it early in the file.
    """
    if data[0x28:0x2c] == _FVH:
        return True
    return _FVH in data[:0x40000]


def _looks_like_name(label: str | None) -> bool:
    return bool(label) and not _GUID_RE.match(label) and not _VER_RE.match(label)


def _content(obj: dict) -> bytes:
    s = obj.get("_self")
    c = getattr(s, "content", None) if s is not None else None
    return c if isinstance(c, (bytes, bytearray)) else b""


def _module_kind(data: bytes) -> str | None:
    if data[:2] == b"MZ":
        return "PE"
    if data[:2] == b"VZ":            # TE (terse executable) image
        return "TE"
    return None


def _iter_files(objs):
    """Yield (file_obj) for every FirmwareFile in the tree."""
    for o in objs:
        if not isinstance(o, dict):
            continue
        if o.get("type") == "FirmwareFile":
            yield o
        yield from _iter_files(o.get("objects") or [])


def _descendants(obj):
    for o in obj.get("objects") or []:
        if isinstance(o, dict):
            yield o
            yield from _descendants(o)


def carve_firmware(path: str, *, extract_dir: str | None = None) -> dict:
    """List (and optionally extract) the PE/TE modules in a UEFI firmware image."""
    if not uefi_available():
        return {"available": False,
                "error": 'uefi_firmware not installed — pip install "chimera[firmware]"'}
    import uefi_firmware

    data = Path(path).read_bytes()
    if not is_uefi_firmware(data):
        return {"available": True, "is_firmware": False,
                "error": "no UEFI firmware volume (_FVH) found"}
    try:
        parsed = uefi_firmware.AutoParser(data).parse()
    except Exception as exc:
        return {"available": True, "is_firmware": True, "error": f"parse failed: {exc}"}
    if parsed is None or not hasattr(parsed, "iterate_objects"):
        return {"available": True, "is_firmware": True,
                "error": "uefi_firmware could not parse this image"}

    out = Path(extract_dir) if extract_dir else None
    if out:
        out.mkdir(parents=True, exist_ok=True)

    modules: list[dict] = []
    seen: set[tuple] = set()
    for f in _iter_files(list(parsed.iterate_objects())):
        guid = f.get("guid") or ""
        body = None
        name = _looks_like_name(f.get("label")) and f.get("label") or None
        for d in _descendants(f):
            c = _content(d)
            if body is None and _module_kind(c):
                body = c
            if name is None and _looks_like_name(d.get("label")):
                name = d.get("label")
        if body is None:
            continue
        key = (guid, len(body))
        if key in seen:
            continue
        seen.add(key)
        entry = {"guid": guid, "name": name, "kind": _module_kind(body),
                 "size": len(body)}
        if out is not None:
            fn = f"{guid}{('_' + re.sub(r'[^A-Za-z0-9._-]', '_', name)) if name else ''}.efi"
            (out / fn).write_bytes(body)
            entry["path"] = str(out / fn)
        modules.append(entry)

    modules.sort(key=lambda m: (m["name"] or "~", m["guid"]))
    return {"available": True, "is_firmware": True, "module_count": len(modules),
            "modules": modules, "extract_dir": str(out) if out else None,
            "note": (f"{len(modules)} PE/TE modules"
                     + (f" extracted to {out}" if out else
                        "; pass extract_dir to write them out"))}
