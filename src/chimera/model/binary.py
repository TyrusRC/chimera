"""Binary metadata model — identifies and classifies mobile app binaries."""

from __future__ import annotations

import hashlib
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

    @property
    def is_mobile(self) -> bool:
        non_mobile = {
            BinaryFormat.PE,
            BinaryFormat.PE32,
            BinaryFormat.PE64,
            BinaryFormat.DOTNET_PE,
            BinaryFormat.DLL,
            BinaryFormat.ELF_STANDALONE,
        }
        return self not in non_mobile


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

    def __post_init__(self):
        pass

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
        if suffix not in (".apk", ".aab", ".xapk", ".apkm", ".apks", ".ipa"):
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
    if magic[:4] == b"PK\x03\x04":
        return _classify_zip(path, suffix)

    if suffix in format_map:
        return format_map[suffix]
    return BinaryFormat.ELF


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
    # Empty or unknown ZIP: fall back to suffix
    return BinaryFormat.IPA if suffix == ".ipa" else BinaryFormat.APK


def _guess_platform(fmt: BinaryFormat) -> Platform:
    android = {BinaryFormat.APK, BinaryFormat.AAB, BinaryFormat.XAPK, BinaryFormat.APKM, BinaryFormat.DEX}
    ios = {BinaryFormat.IPA, BinaryFormat.MACHO, BinaryFormat.FAT, BinaryFormat.DYLIB}
    windows = {BinaryFormat.PE, BinaryFormat.PE32, BinaryFormat.PE64, BinaryFormat.DOTNET_PE, BinaryFormat.DLL}
    linux = {BinaryFormat.ELF_STANDALONE}
    if fmt in android:
        return Platform.ANDROID
    if fmt in ios:
        return Platform.IOS
    if fmt in windows:
        return Platform.WINDOWS
    if fmt in linux:
        return Platform.LINUX_NATIVE
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
