"""Shared pipeline utilities — format detection, unpacking, platform identification."""

from __future__ import annotations

import plistlib
import zipfile
from pathlib import Path


def detect_binary_format(path: Path) -> str:
    path = Path(path)
    magic = b""
    if path.exists() and path.stat().st_size >= 4:
        magic = path.read_bytes()[:4]
    if magic == b"\x7fELF":
        return "elf"
    if magic in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
        return "macho"
    if magic in (b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbe"):
        return "fat"
    if magic[:3] == b"dex":
        return "dex"
    if magic == b"PK\x03\x04" or path.suffix.lower() in (".apk", ".ipa", ".aab", ".xapk"):
        return _detect_zip_format(path)
    ext_map = {".so": "elf", ".dylib": "dylib", ".dll": "dll", ".hbc": "hbc"}
    return ext_map.get(path.suffix.lower(), "unknown")


def _detect_zip_format(path: Path) -> str:
    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = zf.namelist()
            if any(n.startswith("Payload/") and n.endswith(".app/Info.plist") for n in names):
                return "ipa"
            if "AndroidManifest.xml" in names:
                return "apk"
            if "base/manifest/AndroidManifest.xml" in names:
                return "aab"
            if any(n.endswith(".apk") for n in names):
                return "xapk"
    except zipfile.BadZipFile:
        pass
    return "unknown"


def detect_platform(path: Path) -> str:
    fmt = detect_binary_format(path)
    android_formats = {"apk", "aab", "xapk", "dex"}
    ios_formats = {"ipa", "macho", "fat", "dylib"}
    if fmt in android_formats:
        return "android"
    if fmt in ios_formats:
        return "ios"
    if fmt == "elf":
        return "android"
    return "unknown"


def unpack_apk(apk_path: Path, output_dir: Path) -> dict:
    apk_path = Path(apk_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(apk_path, "r") as zf:
        zf.extractall(output_dir)
    manifest_path = output_dir / "AndroidManifest.xml"
    dex_files = sorted(output_dir.glob("classes*.dex"))
    native_libs = []
    lib_dir = output_dir / "lib"
    if lib_dir.exists():
        arch_priority = ["arm64-v8a", "armeabi-v7a", "armeabi"]
        for arch in arch_priority:
            arch_dir = lib_dir / arch
            if arch_dir.exists():
                native_libs = sorted(arch_dir.glob("*.so"))
                break
        if not native_libs:
            native_libs = sorted(lib_dir.rglob("*.so"))
    assets_dir = output_dir / "assets"
    return {
        "output_dir": output_dir,
        "manifest_path": manifest_path,
        "dex_files": dex_files,
        "native_libs": native_libs,
        "assets_dir": assets_dir if assets_dir.exists() else None,
        "has_native": len(native_libs) > 0,
        "dex_count": len(dex_files),
    }


def unpack_ipa(ipa_path: Path, output_dir: Path) -> dict:
    """Unpack an IPA file, extracting app bundle, binary, frameworks, extensions."""
    ipa_path = Path(ipa_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(ipa_path, "r") as zf:
        zf.extractall(output_dir)

    # Find the .app bundle inside Payload/
    payload_dir = output_dir / "Payload"
    app_bundles = list(payload_dir.glob("*.app")) if payload_dir.exists() else []
    app_bundle = app_bundles[0] if app_bundles else None

    if not app_bundle:
        return {
            "output_dir": output_dir,
            "app_bundle": None,
            "main_binary": None,
            "info_plist_path": None,
            "plist": {},
            "bundle_id": None,
            "frameworks": [],
            "extensions": [],
            "has_provision": False,
        }

    # Parse Info.plist
    info_plist_path = app_bundle / "Info.plist"
    plist = {}
    if info_plist_path.exists():
        try:
            plist = plistlib.loads(info_plist_path.read_bytes())
        except Exception:
            pass

    bundle_name = plist.get("CFBundleExecutable", app_bundle.stem)
    bundle_id = plist.get("CFBundleIdentifier", "unknown")

    # Main binary
    main_binary = app_bundle / bundle_name
    if not main_binary.exists():
        # Fallback: find any Mach-O in the app bundle root
        for f in app_bundle.iterdir():
            if f.is_file() and not f.suffix and f.stat().st_size > 1024:
                magic = f.read_bytes()[:4]
                if magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
                             b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
                    main_binary = f
                    break

    # Frameworks
    frameworks_dir = app_bundle / "Frameworks"
    frameworks = []
    if frameworks_dir.exists():
        for fw in frameworks_dir.glob("*.framework"):
            fw_binary = fw / fw.stem
            if fw_binary.exists():
                frameworks.append(fw_binary)

    # Extensions
    plugins_dir = app_bundle / "PlugIns"
    extensions = []
    if plugins_dir.exists():
        for ext in plugins_dir.glob("*.appex"):
            ext_binary = ext / ext.stem
            if ext_binary.exists():
                extensions.append(ext_binary)

    # Provisioning profile
    has_provision = (app_bundle / "embedded.mobileprovision").exists()

    return {
        "output_dir": output_dir,
        "app_bundle": app_bundle,
        "main_binary": main_binary if main_binary.exists() else None,
        "info_plist_path": info_plist_path,
        "plist": plist,
        "bundle_id": bundle_id,
        "frameworks": frameworks,
        "extensions": extensions,
        "has_provision": has_provision,
    }
