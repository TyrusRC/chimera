"""Shared pipeline utilities — format detection, unpacking, platform identification."""

from __future__ import annotations

import json
import logging
import plistlib
import zipfile
from pathlib import Path

logger = logging.getLogger(__name__)


def detect_binary_format(path: Path) -> str:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"binary not found: {path}")
    if path.stat().st_size < 4:
        raise ValueError(f"binary too short to identify ({path.stat().st_size} bytes): {path}")

    with open(path, "rb") as fh:
        magic = fh.read(8)

    if magic[:4] == b"\x7fELF":
        return "elf"
    if magic[:4] in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
        return "macho"
    if magic[:4] in (b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbe"):
        return "fat"
    if magic[:3] == b"dex":
        return "dex"
    if magic[:4] == b"PK\x03\x04" or path.suffix.lower() in (".apk", ".ipa", ".aab", ".xapk", ".apkm", ".apks"):
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
            # APKM: APKMirror bundle — has info.json + base.apk + split_config.*.apk
            if "info.json" in names and any(n.endswith(".apk") for n in names):
                return "apkm"
            # XAPK: has manifest.json + split APKs
            if "manifest.json" in names and any(n.endswith(".apk") for n in names):
                return "xapk"
            # Generic split APK bundle (e.g. .apks from SAI)
            if any(n.endswith(".apk") for n in names):
                return "xapk"
    except zipfile.BadZipFile:
        pass
    return "unknown"


def detect_platform(path: Path) -> str:
    fmt = detect_binary_format(path)
    android_formats = {"apk", "aab", "xapk", "apkm", "dex"}
    ios_formats = {"ipa", "macho", "fat", "dylib"}
    if fmt in android_formats:
        return "android"
    if fmt in ios_formats:
        return "ios"
    if fmt == "elf":
        return "android"
    return "unknown"


def _find_base_apk_in_bundle(bundle_path: Path, output_dir: Path) -> Path:
    """Extract a split APK bundle (XAPK/APKM/APKS) and return the path to the base APK."""
    output_dir.mkdir(parents=True, exist_ok=True)
    bundle_dir = output_dir / "_bundle"
    bundle_dir.mkdir(parents=True, exist_ok=True)

    extraction_succeeded = False
    try:
        with zipfile.ZipFile(bundle_path, "r") as zf:
            zf.extractall(bundle_dir)

        base_apk = bundle_dir / "base.apk"
        if base_apk.exists():
            logger.info("Found base.apk in bundle")
            extraction_succeeded = True
            return base_apk

        manifest_json = bundle_dir / "manifest.json"
        if manifest_json.exists():
            try:
                manifest = json.loads(manifest_json.read_text())
                package_name = manifest.get("package_name", "")
                split_apks = manifest.get("split_apks", [])
                for split in split_apks:
                    file_name = split.get("file", "")
                    apk_id = split.get("id", "")
                    if apk_id == "base" or file_name == f"{package_name}.apk":
                        candidate = bundle_dir / file_name
                        if candidate.exists():
                            logger.info("Found base APK from manifest.json: %s", file_name)
                            extraction_succeeded = True
                            return candidate
                for split in split_apks:
                    file_name = split.get("file", "")
                    if not file_name.startswith("config.") and not file_name.startswith("split_config."):
                        candidate = bundle_dir / file_name
                        if candidate.exists():
                            logger.info("Using non-config APK as base: %s", file_name)
                            extraction_succeeded = True
                            return candidate
            except (json.JSONDecodeError, OSError):
                pass

        all_apks = sorted(bundle_dir.glob("*.apk"), key=lambda p: p.stat().st_size, reverse=True)
        if all_apks:
            max_size = all_apks[0].stat().st_size
            close_ties = [p for p in all_apks[1:] if p.stat().st_size >= 0.9 * max_size]
            if close_ties:
                names = [all_apks[0].name] + [p.name for p in close_ties]
                raise ValueError(
                    f"ambiguous base APK in bundle — multiple large APKs: {names}"
                )
            logger.info("Fallback: using largest APK as base: %s (%d bytes)",
                        all_apks[0].name, max_size)
            extraction_succeeded = True
            return all_apks[0]

        raise FileNotFoundError(f"No base APK found in bundle: {bundle_path}")
    finally:
        if not extraction_succeeded:
            import shutil as _sh
            _sh.rmtree(bundle_dir, ignore_errors=True)


def _collect_split_native_libs(bundle_dir: Path) -> list[Path]:
    """Collect native .so files from architecture-specific split APKs in a bundle."""
    native_libs = []
    arch_priority = ["arm64_v8a", "arm64-v8a", "armeabi_v7a", "armeabi-v7a"]
    for arch in arch_priority:
        for apk_path in bundle_dir.glob(f"*{arch}*"):
            if apk_path.suffix == ".apk":
                try:
                    with zipfile.ZipFile(apk_path, "r") as zf:
                        for name in zf.namelist():
                            if name.endswith(".so") and name.startswith("lib/"):
                                extract_dir = bundle_dir / f"_split_{apk_path.stem}"
                                extract_dir.mkdir(parents=True, exist_ok=True)
                                zf.extract(name, extract_dir)
                                native_libs.append(extract_dir / name)
                except zipfile.BadZipFile:
                    continue
        if native_libs:
            break
    return native_libs


def unpack_apk(apk_path: Path, output_dir: Path) -> dict:
    apk_path = Path(apk_path)
    output_dir = Path(output_dir)
    fmt = detect_binary_format(apk_path)

    # Handle split APK bundles (XAPK, APKM, APKS)
    if fmt in ("xapk", "apkm"):
        logger.info("Detected split APK bundle (%s) — extracting base APK", fmt)
        base_apk = _find_base_apk_in_bundle(apk_path, output_dir)
        bundle_dir = output_dir / "_bundle"

        # Unpack the base APK
        base_output = output_dir / "base"
        base_output.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(base_apk, "r") as zf:
            zf.extractall(base_output)

        manifest_path = base_output / "AndroidManifest.xml"
        dex_files = sorted(base_output.glob("classes*.dex"))

        # Native libs: first from the base APK, then from arch-specific split APKs
        native_libs = []
        lib_dir = base_output / "lib"
        if lib_dir.exists():
            arch_priority = ["arm64-v8a", "armeabi-v7a", "armeabi"]
            for arch in arch_priority:
                arch_dir = lib_dir / arch
                if arch_dir.exists():
                    native_libs = sorted(arch_dir.glob("*.so"))
                    break
            if not native_libs:
                native_libs = sorted(lib_dir.rglob("*.so"))

        # Also collect native libs from split config APKs (e.g. config.arm64_v8a.apk)
        if not native_libs:
            native_libs = _collect_split_native_libs(bundle_dir)

        assets_dir = base_output / "assets"

        # Read bundle metadata for extra context
        bundle_meta = {}
        for meta_name in ("manifest.json", "info.json"):
            meta_path = bundle_dir / meta_name
            if meta_path.exists():
                try:
                    bundle_meta = json.loads(meta_path.read_text())
                except (json.JSONDecodeError, OSError):
                    pass
                break

        return {
            "output_dir": base_output,
            "manifest_path": manifest_path,
            "dex_files": dex_files,
            "native_libs": native_libs,
            "assets_dir": assets_dir if assets_dir.exists() else None,
            "has_native": len(native_libs) > 0,
            "dex_count": len(dex_files),
            "bundle_format": fmt,
            "bundle_meta": bundle_meta,
            "base_apk_path": base_apk,
        }

    # Standard APK
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


def _rehydrate_from_cache(model, cache, sha256: str, *, language: str, layer: str) -> None:
    """Replay r2_* cache entries into the model's functions + strings on a cache hit.

    Cold-path populates the model only from r2 output; jadx/ghidra go to cache-only.
    So rehydration reads each r2_<lib> entry and replays the same add_* calls.
    """
    from chimera.model.function import FunctionInfo
    from chimera.pipelines.android import _valid_r2_string, _valid_r2_function

    # cache._entry_dir is the internal helper in core/cache.py that returns
    # cache_dir / sha256[:2] / sha256 — used because there's no public iterator.
    entry_dir = cache._entry_dir(sha256)
    if not entry_dir.exists():
        return
    for category_file in entry_dir.iterdir():
        name = category_file.name
        if not name.startswith("r2_"):
            continue
        triage = cache.get_json(sha256, name)
        if not isinstance(triage, dict):
            continue
        for s in triage.get("strings", []):
            if not _valid_r2_string(s):
                continue
            model.add_string(
                address=str(s.get("vaddr", "0x0")),
                value=s["string"],
                section=s.get("section", None),
            )
        for f in triage.get("functions", []):
            if not _valid_r2_function(f):
                continue
            off = f.get("offset", f.get("vaddr"))
            addr = hex(off) if isinstance(off, int) else str(off)
            fname = f.get("name") or f.get("realname") or f"FUN_{addr}"
            model.add_function(FunctionInfo(
                address=addr, name=fname, original_name=fname,
                language=language, classification="unknown",
                layer=layer, source_backend="radare2",
            ))
