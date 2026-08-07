"""Shared pipeline utilities — format detection, unpacking, platform identification."""

from __future__ import annotations

import json
import logging
import plistlib
import zipfile
from pathlib import Path

from chimera.core.addr import normalize_address as _norm_addr
from chimera.pipelines.safe_extract import safe_extract_zip

logger = logging.getLogger(__name__)


def _classify_elf_context(path: Path) -> str:
    """Distinguish Android JNI .so from standalone Linux ELF.

    Inspects DT_NEEDED via pyelftools (`parse_elf`). Returns "elf"
    (Android JNI context) when the ELF declares any Bionic-only library
    in its dynamic NEEDED list (`liblog.so`, `libandroid.so`,
    `libbinder_ndk.so`, `libnativehelper.so`, etc). Otherwise returns
    "elf_standalone".

    Falls back to a coarse byte-level scan if pyelftools is unavailable
    or the ELF is malformed enough to make pyelftools raise — analysts
    dropping a corrupt binary expect best-effort triage rather than a
    hard failure.
    """
    bionic_libs = {
        "liblog.so", "libandroid.so", "libbinder_ndk.so",
        "libnativehelper.so", "libmediandk.so", "libcamera2ndk.so",
        "libnativewindow.so", "libamidi.so",
    }
    try:
        from chimera.parsers.elf_header import parse_elf
        info = parse_elf(path)
        for needed in info.needed:
            if needed in bionic_libs:
                return "elf"
        return "elf_standalone"
    except Exception:
        # Fallback: byte-level scan of the first 16 KB.
        try:
            with open(path, "rb") as fh:
                head = fh.read(16 * 1024)
        except OSError:
            return "elf_standalone"
        if b"liblog.so" in head or b"libandroid.so" in head:
            return "elf"
        return "elf_standalone"


def _classify_pe_string(path: Path) -> str:
    """PE32 / PE32+ / .NET label as a string. Delegates to the model-layer
    classifier so the header walk lives in exactly one place."""
    from chimera.model.binary import classify_pe_bytes

    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return "pe32"
    return classify_pe_bytes(data)


def detect_binary_format(path: Path) -> str:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"binary not found: {path}")
    if path.stat().st_size < 4:
        raise ValueError(f"binary too short to identify ({path.stat().st_size} bytes): {path}")

    with open(path, "rb") as fh:
        magic = fh.read(8)

    if magic[:4] == b"\x7fELF":
        return _classify_elf_context(path)
    if magic[:4] in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
        return "macho"
    if magic[:4] in (b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbe"):
        return "fat"
    if magic[:3] == b"dex":
        return "dex"
    if magic[:4] == b"PK\x03\x04" or path.suffix.lower() in (".apk", ".ipa", ".aab", ".xapk", ".apkm", ".apks"):
        return _detect_zip_format(path)
    if magic[:2] == b"MZ":
        return _classify_pe_string(path)
    if magic[:4] in (b"LiME", b"EMiL"):
        return "memory_lime"

    suffix = path.suffix.lower()
    if suffix in (".raw", ".mem", ".dmp", ".vmem"):
        return "memory_raw"
    if suffix == ".lime":
        return "memory_lime"
    ext_map = {".so": "elf", ".dylib": "dylib", ".dll": "dll", ".hbc": "hbc"}
    return ext_map.get(suffix, "unknown")


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
    windows_formats = {"pe32", "pe64", "dotnet_pe", "dll"}
    memory_formats = {"memory_lime", "memory_raw"}
    if fmt in android_formats:
        return "android"
    if fmt in ios_formats:
        return "ios"
    if fmt in windows_formats:
        return "windows"
    if fmt == "elf_standalone":
        return "linux_native"
    if fmt in memory_formats:
        return "linux_memory"
    if fmt == "elf":
        return "android"  # JNI library context
    return "unknown"


def _find_base_apk_in_bundle(bundle_path: Path, output_dir: Path) -> Path:
    """Extract a split APK bundle (XAPK/APKM/APKS) and return the path to the base APK."""
    output_dir.mkdir(parents=True, exist_ok=True)
    bundle_dir = output_dir / "_bundle"
    bundle_dir.mkdir(parents=True, exist_ok=True)

    extraction_succeeded = False
    try:
        safe_extract_zip(bundle_path, bundle_dir)

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
        safe_extract_zip(base_apk, base_output)

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
    safe_extract_zip(apk_path, output_dir)
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

    safe_extract_zip(ipa_path, output_dir)

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
        except (plistlib.InvalidFileException, OSError, ValueError) as exc:
            logger.warning("failed to parse %s: %s", info_plist_path, exc)

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


def should_deepen_r2(func_count: int, *, deep: bool = False, min_functions: int = 3) -> bool:
    """Whether to run r2's analysis pass (`aaa`) after symbol-table triage.

    Native pipelines seed functions from r2's symbol table (`isj`), which finds
    ~nothing on a stripped binary — exactly the case RE tools exist for. Escalate
    to `aaa`/`aflj` when the operator opted in (`deep`) or triage clearly
    under-recovered (fewer than `min_functions`).
    """
    if deep:
        return True
    return func_count < max(1, min_functions)


async def deepen_r2_functions(r2_adapter, path, model, *, language: str = "c",
                              layer: str = "native") -> int:
    """Run r2's analysis pass to recover functions the symbol table omits.

    Merges results into the model (existing addresses dedup via add_function).
    Returns the number of NEW functions added.
    """
    from chimera.model.function import FunctionInfo

    result = await r2_adapter.analyze(str(path), {"mode": "functions"})
    added = 0
    for f in result.get("functions", []) or []:
        if not isinstance(f, dict):
            continue
        off = f.get("offset", f.get("vaddr"))
        if not isinstance(off, (int, str)):
            continue
        addr = hex(off) if isinstance(off, int) else str(off)
        name = f.get("name") or f.get("realname") or f"FUN_{addr}"
        is_new = model.get_function(addr) is None
        model.add_function(FunctionInfo(
            address=addr, name=name, original_name=name, language=language,
            classification="unknown", layer=layer, source_backend="radare2",
        ))
        if is_new:
            added += 1
    return added


def ingest_ghidra_functions(
    model, ghidra_result: dict, *, language: str = "c", layer: str = "native",
) -> int:
    """Merge Ghidra's exported functions + decompiled C into the model.

    The Ghidra post-script (`ExportFunctions.java`) writes `functions.json`
    (name/address/size) and `decompilations.json` (address/name/code). The
    native pipelines previously cached this blob and discarded it, so
    `FunctionInfo.decompiled` was never populated for native code. This helper
    replays it into the model: functions r2 already seeded (matched by
    normalized address) get their decompiled C backfilled via the merge in
    `UnifiedProgramModel.add_function`; Ghidra-only functions are added fresh.

    Returns the number of functions that received decompiled C. Tolerant of a
    missing/failed Ghidra result (returns 0) so callers can invoke it
    unconditionally.
    """
    from chimera.model.function import FunctionInfo

    if not isinstance(ghidra_result, dict):
        return 0

    code_by_addr: dict[str, str] = {}
    for d in ghidra_result.get("decompilations", []) or []:
        if not isinstance(d, dict):
            continue
        code = d.get("code")
        addr = d.get("address")
        if code and addr is not None:
            code_by_addr[_norm_addr(addr)] = code

    ingested = 0
    seen: set[str] = set()
    for f in ghidra_result.get("functions", []) or []:
        if not isinstance(f, dict):
            continue
        addr_raw = f.get("address")
        if addr_raw is None:
            continue
        addr = _norm_addr(addr_raw)
        seen.add(addr)
        code = code_by_addr.get(addr)
        name = f.get("name") or f"FUN_{addr}"
        model.add_function(FunctionInfo(
            address=addr, name=name, original_name=name,
            language=language, classification="unknown",
            layer=layer, source_backend="ghidra", decompiled=code,
        ))
        if code:
            ingested += 1

    # Decompilations for functions Ghidra's function iterator didn't list
    # (rare, but don't silently drop the C we paid to produce).
    for addr, code in code_by_addr.items():
        if addr in seen:
            continue
        model.add_function(FunctionInfo(
            address=addr, name=f"FUN_{addr}", original_name=f"FUN_{addr}",
            language=language, classification="unknown",
            layer=layer, source_backend="ghidra", decompiled=code,
        ))
        ingested += 1

    return ingested


def _rehydrate_from_cache(model, cache, sha256: str, *, language: str, layer: str) -> None:
    """Replay r2_* cache entries into the model's functions + strings on a cache hit.

    Cold-path populates the model only from r2 output; jadx/ghidra go to cache-only.
    So rehydration reads each r2_<lib> entry and replays the same add_* calls.
    """
    from chimera.model.function import FunctionInfo
    from chimera.pipelines.android import _valid_r2_string, _valid_r2_function

    keys = cache.list_keys(sha256)
    for name in keys:
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

    # Second pass: replay cached Ghidra output so warm-cache runs recover the
    # decompiled C too (r2 must be replayed first so the address merge backfills
    # onto the existing functions rather than duplicating them).
    for name in keys:
        if not name.startswith("ghidra_"):
            continue
        ghidra_result = cache.get_json(sha256, name)
        ingest_ghidra_functions(model, ghidra_result, language=language, layer=layer)


def find_mapping_file(unpack_dir: Path, apk_path: Path | None = None) -> Path | None:
    """Locate a ProGuard/R8 mapping file to restore original identifiers.

    Search order:
      1. Sibling of the APK on disk: <apk>.mapping, <apk>.mapping.txt
      2. Inside AAB bundle:          <unpack>/BUNDLE-METADATA/com.android.tools.build.obfuscation/proguard.map
      3. Bundled in APK:             <unpack>/assets/mapping.txt, <unpack>/mapping.txt

    Returns the first existing hit. Never raises — missing sources fall through.
    """
    if apk_path is not None:
        for candidate in (
            apk_path.with_suffix(apk_path.suffix + ".mapping"),
            apk_path.with_suffix(apk_path.suffix + ".mapping.txt"),
        ):
            if candidate.exists():
                return candidate

    aab_path = unpack_dir / "BUNDLE-METADATA" / "com.android.tools.build.obfuscation" / "proguard.map"
    if aab_path.exists():
        return aab_path

    for candidate in (
        unpack_dir / "assets" / "mapping.txt",
        unpack_dir / "mapping.txt",
    ):
        if candidate.exists():
            return candidate

    return None


_KOTLIN_METADATA_MARKER = b"Lkotlin/Metadata;"


def detect_kotlin(unpack_dir: Path) -> bool:
    """Return True if any classes*.dex in unpack_dir references kotlin.Metadata.

    Byte-scan only — no full DEX parse. Short-circuits on first match.
    Kotlin apps carry `@kotlin.Metadata` annotations whose class descriptor
    `Lkotlin/Metadata;` appears in the DEX string table.
    """
    for dex in sorted(unpack_dir.glob("classes*.dex")):
        try:
            with open(dex, "rb") as fh:
                if _KOTLIN_METADATA_MARKER in fh.read():
                    return True
        except OSError:
            continue
    return False
