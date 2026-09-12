"""Assemble mnemonics → machine-code bytes (keystone) — the input side of the patcher.

`BinaryPatcher` rewrites raw bytes; without an assembler every patch means
hand-encoding x86/ARM: computing REX prefixes and, worse, PC-relative jump/branch
displacements — the exact step most likely to go silently wrong. This wraps
keystone so a patch can be written as ``"xor eax, eax; ret"`` and assembled *at the
target VA* (so a relative branch encodes the right displacement). keystone is an
optional extra (`chimera[patch]`); without it `assemble` raises `AssembleError`
with a clear install hint rather than an ImportError.
"""
from __future__ import annotations


class AssembleError(Exception):
    """keystone missing, an unknown arch, or a source line that won't assemble."""


# name → (KS_ARCH attr, KS_MODE attr). Resolved lazily so importing this module
# never requires keystone. Aliases point at the same pair.
_ARCH_SPECS: dict[str, tuple[str, str]] = {
    "x86_64": ("KS_ARCH_X86", "KS_MODE_64"),
    "x86": ("KS_ARCH_X86", "KS_MODE_32"),
    "x86_32": ("KS_ARCH_X86", "KS_MODE_32"),
    "arm64": ("KS_ARCH_ARM64", "KS_MODE_LITTLE_ENDIAN"),
    "aarch64": ("KS_ARCH_ARM64", "KS_MODE_LITTLE_ENDIAN"),
    "arm": ("KS_ARCH_ARM", "KS_MODE_ARM"),
    "thumb": ("KS_ARCH_ARM", "KS_MODE_THUMB"),
}

SUPPORTED_ARCHES = tuple(_ARCH_SPECS)


def keystone_available() -> bool:
    try:
        import keystone  # noqa: F401
        return True
    except Exception:
        return False


def assemble(code: str, arch: str = "x86_64", addr: int = 0) -> bytes:
    """Assemble `code` (one or more ``;``/newline-separated instructions) to bytes.

    `arch` is one of SUPPORTED_ARCHES. `addr` is the virtual address the bytes will
    live at — keystone uses it to encode PC-relative branches, so passing the real
    patch VA is what makes a ``jmp``/``call``/``b`` land where intended.
    """
    spec = _ARCH_SPECS.get(arch.lower())
    if spec is None:
        raise AssembleError(
            f"unknown asm arch {arch!r}; supported: {', '.join(SUPPORTED_ARCHES)}")
    try:
        import keystone
    except Exception as exc:  # pragma: no cover - exercised only without the extra
        raise AssembleError(
            'keystone not installed — pip install "chimera[patch]"') from exc

    ks = keystone.Ks(getattr(keystone, spec[0]), getattr(keystone, spec[1]))
    try:
        encoding, _count = ks.asm(code, addr)
    except keystone.KsError as exc:
        raise AssembleError(f"could not assemble {code!r} for {arch}: {exc}") from exc
    if not encoding:
        raise AssembleError(f"assembled to zero bytes: {code!r}")
    return bytes(encoding)
