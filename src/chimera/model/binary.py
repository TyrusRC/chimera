"""Binary metadata model — identifies and classifies mobile app binaries."""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class BinaryFormat(Enum):
    APK = "apk"
    AAB = "aab"
    XAPK = "xapk"
    APKM = "apkm"
    IPA = "ipa"
    DEX = "dex"
    ELF = "elf"
    MACHO = "macho"
    FAT = "fat"
    DYLIB = "dylib"
    HBC = "hbc"
    DART_AOT = "dart_aot"
    DLL = "dll"
    IL2CPP = "il2cpp"
    JS_BUNDLE = "js_bundle"
    PE = "pe"
    PE32 = "pe32"
    PE64 = "pe64"
    DOTNET_PE = "dotnet_pe"
    ELF_STANDALONE = "elf_standalone"
    MEMORY_LIME = "memory_lime"
    MEMORY_RAW = "memory_raw"
    JAR = "jar"

    @property
    def is_mobile(self) -> bool:
        non_mobile = {
            BinaryFormat.PE,
            BinaryFormat.PE32,
            BinaryFormat.PE64,
            BinaryFormat.DOTNET_PE,
            BinaryFormat.DLL,
            BinaryFormat.ELF_STANDALONE,
            BinaryFormat.MEMORY_LIME,
            BinaryFormat.MEMORY_RAW,
        }
        return self not in non_mobile

    @property
    def is_memory_image(self) -> bool:
        return self in {BinaryFormat.MEMORY_LIME, BinaryFormat.MEMORY_RAW}


class Architecture(Enum):
    ARM32 = "arm32"
    ARM64 = "arm64"
    ARM64E = "arm64e"
    DEX = "dex"
    HERMES = "hermes"
    DART = "dart"
    DOTNET_IL = "dotnet_il"
    X86 = "x86"
    X86_64 = "x86_64"
    MIPS = "mips"
    RISCV = "riscv"
    UNKNOWN = "unknown"


class Platform(Enum):
    ANDROID = "android"
    IOS = "ios"
    WINDOWS = "windows"
    LINUX_NATIVE = "linux_native"
    LINUX_MEMORY = "linux_memory"
    JVM = "jvm"
    UNKNOWN = "unknown"


class Framework(Enum):
    NONE = "none"
    NATIVE = "native"
    REACT_NATIVE = "react-native"
    FLUTTER = "flutter"
    XAMARIN = "xamarin"
    UNITY_IL2CPP = "unity-il2cpp"
    CORDOVA = "cordova"
    IONIC = "ionic"
    CAPACITOR = "capacitor"
    KMM = "kmm"
    PYINSTALLER = "pyinstaller"
    VB6 = "vb6"  # classic Visual Basic 6 or twinBASIC (VB6-compatible)
    UNKNOWN = "unknown"


@dataclass
class BinaryInfo:
    sha256: str
    path: Path
    format: BinaryFormat
    platform: Platform
    arch: Architecture
    framework: Framework
    size_bytes: int
    package_name: Optional[str] = None
    version: Optional[str] = None
    min_sdk: Optional[int] = None
    sub_binaries: list[BinaryInfo] = field(default_factory=list)

    @property
    def is_mobile(self) -> bool:
        return self.format.is_mobile

    @classmethod
    def from_path(cls, path: Path) -> BinaryInfo:
        path = Path(path)
        sha256 = _compute_sha256(path)
        size = path.stat().st_size
        fmt = _detect_format(path)
        platform = _guess_platform(fmt)
        arch = _guess_arch(fmt)
        return cls(
            sha256=sha256, path=path, format=fmt, platform=platform,
            arch=arch, framework=Framework.UNKNOWN, size_bytes=size,
        )


def _compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _detect_format(path: Path) -> BinaryFormat:
    suffix = path.suffix.lower()
    format_map = {
        ".apk": BinaryFormat.APK, ".aab": BinaryFormat.AAB,
        ".xapk": BinaryFormat.XAPK, ".apkm": BinaryFormat.APKM,
        ".apks": BinaryFormat.XAPK, ".ipa": BinaryFormat.IPA,
        ".dex": BinaryFormat.DEX, ".so": BinaryFormat.ELF,
        ".dylib": BinaryFormat.DYLIB, ".dll": BinaryFormat.DLL,
        ".hbc": BinaryFormat.HBC,
    }
    if suffix in format_map:
        # Even with a "known" suffix, an IPA may be mislabeled .zip; disambiguate ZIPs below
        # Also, .dll may be a .NET PE, so check magic bytes
        if suffix not in (".apk", ".aab", ".xapk", ".apkm", ".apks", ".ipa", ".dll"):
            return format_map[suffix]

    with open(path, "rb") as fh:
        magic = fh.read(8)

    if magic[:4] == b"\x7fELF":
        return BinaryFormat.ELF
    if magic[:4] in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
        return BinaryFormat.MACHO
    if magic[:4] in (b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbe"):
        return BinaryFormat.FAT
    if magic[:4] == b"dex\n":
        return BinaryFormat.DEX
    if magic[:2] == b"MZ":
        return _classify_pe(path)
    if magic[:4] == b"PK\x03\x04":
        return _classify_zip(path, suffix)
    if magic[:4] in (b"LiME", b"EMiL"):
        return BinaryFormat.MEMORY_LIME

    if suffix in (".raw", ".mem", ".dmp", ".vmem"):
        return BinaryFormat.MEMORY_RAW
    if suffix == ".lime":
        return BinaryFormat.MEMORY_LIME
    if suffix in format_map:
        return format_map[suffix]
    return BinaryFormat.ELF


_PE_STR_TO_FORMAT = {
    "pe32": BinaryFormat.PE32,
    "pe64": BinaryFormat.PE64,
    "dotnet_pe": BinaryFormat.DOTNET_PE,
}


def classify_pe_bytes(data: bytes) -> str:
    """Walk a PE image's headers to label it 'pe32' | 'pe64' | 'dotnet_pe'.

    The single source of truth for PE classification — `_classify_pe` maps the
    result to a `BinaryFormat`, and `pipelines.common._classify_pe_string`
    reuses it verbatim. Returns the stable default 'pe32' on malformed input
    rather than raising; analysts dropping a corrupt binary expect best-effort
    triage.
    """
    if len(data) < 0x40 or data[:2] != b"MZ":
        return "pe32"

    # e_lfanew at 0x3C, uint32 little-endian. len >= 0x40 guarantees this read.
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_off + 24 > len(data) or data[pe_off:pe_off + 4] != b"PE\x00\x00":
        return "pe32"

    # IMAGE_FILE_HEADER is 20 bytes starting at pe_off+4.
    # IMAGE_OPTIONAL_HEADER.Magic is uint16 LE at pe_off+24.
    optional_magic = struct.unpack_from("<H", data, pe_off + 24)[0]

    # IMAGE_DATA_DIRECTORY[14] (CLR header) lives at:
    #   PE32  (Magic 0x10b) -> pe_off + 24 + 208
    #   PE32+ (Magic 0x20b) -> pe_off + 24 + 224
    clr_off = pe_off + 24 + (224 if optional_magic == 0x20b else 208)
    if clr_off + 8 <= len(data):
        clr_va, clr_size = struct.unpack_from("<II", data, clr_off)
        if clr_va != 0 and clr_size != 0:
            return "dotnet_pe"

    return "pe64" if optional_magic == 0x20b else "pe32"


def _classify_pe(path: Path) -> BinaryFormat:
    """Distinguish PE32, PE32+, and .NET PE for `_detect_format`."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return BinaryFormat.PE32
    return _PE_STR_TO_FORMAT[classify_pe_bytes(data)]


def _classify_zip(path: Path, suffix: str) -> BinaryFormat:
    """Inspect the ZIP central directory to decide APK vs IPA vs AAB."""
    import zipfile

    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = zf.namelist()
    except zipfile.BadZipFile:
        return BinaryFormat.APK if suffix != ".ipa" else BinaryFormat.IPA

    if any(n.startswith("Payload/") and n.endswith(".app/Info.plist") for n in names):
        return BinaryFormat.IPA
    if "AndroidManifest.xml" in names:
        return BinaryFormat.APK
    if "base/manifest/AndroidManifest.xml" in names:
        return BinaryFormat.AAB
    if any(n.endswith(".apk") for n in names):
        if suffix == ".apkm":
            return BinaryFormat.APKM
        return BinaryFormat.XAPK
    # Checked last: an APK is also a zip of .class-bearing dex, so every
    # Android shape above must get first refusal.
    if any(n.endswith(".class") for n in names):
        return BinaryFormat.JAR
    # Empty or unknown ZIP: fall back to suffix
    return BinaryFormat.IPA if suffix == ".ipa" else BinaryFormat.APK


def _guess_platform(fmt: BinaryFormat) -> Platform:
    android = {BinaryFormat.APK, BinaryFormat.AAB, BinaryFormat.XAPK, BinaryFormat.APKM, BinaryFormat.DEX}
    ios = {BinaryFormat.IPA, BinaryFormat.MACHO, BinaryFormat.FAT, BinaryFormat.DYLIB}
    windows = {BinaryFormat.PE, BinaryFormat.PE32, BinaryFormat.PE64, BinaryFormat.DOTNET_PE, BinaryFormat.DLL}
    linux = {BinaryFormat.ELF_STANDALONE}
    memory = {BinaryFormat.MEMORY_LIME, BinaryFormat.MEMORY_RAW}
    if fmt in android:
        return Platform.ANDROID
    if fmt in ios:
        return Platform.IOS
    if fmt in windows:
        return Platform.WINDOWS
    if fmt == BinaryFormat.JAR:
        return Platform.JVM
    if fmt in linux:
        return Platform.LINUX_NATIVE
    if fmt in memory:
        return Platform.LINUX_MEMORY
    if fmt == BinaryFormat.ELF:
        return Platform.ANDROID  # JNI .so default
    return Platform.UNKNOWN


def _guess_arch(fmt: BinaryFormat) -> Architecture:
    if fmt == BinaryFormat.DEX:
        return Architecture.DEX
    if fmt == BinaryFormat.HBC:
        return Architecture.HERMES
    if fmt in (BinaryFormat.MACHO, BinaryFormat.FAT, BinaryFormat.IPA):
        return Architecture.ARM64
    if fmt in (BinaryFormat.PE64, BinaryFormat.DOTNET_PE):
        return Architecture.X86_64
    if fmt == BinaryFormat.PE32:
        return Architecture.X86
    if fmt == BinaryFormat.ELF_STANDALONE:
        return Architecture.X86_64  # default; refined later via parse_elf
    return Architecture.UNKNOWN
