"""Framework detector — identifies which cross-platform framework an app uses."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class DetectedFramework:
    framework: str     # native, react-native, flutter, xamarin, unity-il2cpp, cordova, capacitor, ionic
    variant: Optional[str] = None  # hermes/jsc for RN, obfuscated/clear for Flutter
    confidence: float = 1.0
    details: Optional[str] = None


# Hermes bytecode magic: 0xc61fbc03
_HERMES_MAGIC = b"\xc6\x1f\xbc\x03"

# IL2CPP global-metadata magic: 0xFAB11BAF
_IL2CPP_METADATA_MAGIC = b"\xaf\x1b\xb1\xfa"


class FrameworkDetector:
    @staticmethod
    def detect(unpack_dir: Path) -> DetectedFramework:
        """Detect framework from unpacked app contents. Checks in priority order."""
        unpack_dir = Path(unpack_dir)

        # Flutter (Android: libflutter.so + libapp.so, iOS: Flutter.framework)
        result = _check_flutter(unpack_dir)
        if result:
            return result

        # React Native (assets/index.android.bundle or main.jsbundle)
        result = _check_react_native(unpack_dir)
        if result:
            return result

        # Unity IL2CPP (libil2cpp.so + global-metadata.dat)
        result = _check_unity(unpack_dir)
        if result:
            return result

        # Xamarin (assemblies/ directory)
        result = _check_xamarin(unpack_dir)
        if result:
            return result

        # Cordova/Ionic/Capacitor (assets/www or assets/public)
        result = _check_webview_framework(unpack_dir)
        if result:
            return result

        return DetectedFramework(framework="native")


def _check_flutter(unpack_dir: Path) -> DetectedFramework | None:
    # Android
    for arch in ["arm64-v8a", "armeabi-v7a", "x86_64"]:
        lib_dir = unpack_dir / "lib" / arch
        if (lib_dir / "libflutter.so").exists() and (lib_dir / "libapp.so").exists():
            return DetectedFramework(framework="flutter", details=f"Android ({arch})")

    # iOS
    flutter_fw = unpack_dir / "Frameworks" / "Flutter.framework"
    app_fw = unpack_dir / "Frameworks" / "App.framework"
    if flutter_fw.exists() and app_fw.exists():
        return DetectedFramework(framework="flutter", details="iOS")

    return None


def _check_react_native(unpack_dir: Path) -> DetectedFramework | None:
    # Android bundle
    bundle_paths = [
        unpack_dir / "assets" / "index.android.bundle",
        unpack_dir / "assets" / "index.bundle",
    ]
    # iOS bundle
    bundle_paths.extend(unpack_dir.glob("*.jsbundle"))
    bundle_paths.extend(unpack_dir.glob("main.jsbundle"))

    for bundle in bundle_paths:
        if bundle.exists() and bundle.stat().st_size > 0:
            magic = bundle.read_bytes()[:4]
            if magic == _HERMES_MAGIC:
                return DetectedFramework(framework="react-native", variant="hermes",
                                         details=f"Hermes bytecode: {bundle.name}")
            else:
                return DetectedFramework(framework="react-native", variant="jsc",
                                         details=f"JSC bundle: {bundle.name}")
    return None


def _check_unity(unpack_dir: Path) -> DetectedFramework | None:
    # Android
    for arch in ["arm64-v8a", "armeabi-v7a"]:
        il2cpp = unpack_dir / "lib" / arch / "libil2cpp.so"
        if il2cpp.exists():
            # Look for global-metadata.dat
            for metadata in unpack_dir.rglob("global-metadata.dat"):
                magic = metadata.read_bytes()[:4]
                if magic == _IL2CPP_METADATA_MAGIC:
                    return DetectedFramework(framework="unity-il2cpp",
                                             details=f"IL2CPP with metadata ({arch})")
            return DetectedFramework(framework="unity-il2cpp", variant="no-metadata",
                                     details=f"IL2CPP without metadata ({arch})", confidence=0.8)

    # iOS
    game_asm = unpack_dir / "Frameworks" / "GameAssembly.framework"
    if game_asm.exists():
        for metadata in unpack_dir.rglob("global-metadata.dat"):
            return DetectedFramework(framework="unity-il2cpp", details="iOS IL2CPP with metadata")
        return DetectedFramework(framework="unity-il2cpp", variant="no-metadata",
                                 details="iOS IL2CPP without metadata", confidence=0.8)

    return None


def _check_xamarin(unpack_dir: Path) -> DetectedFramework | None:
    assemblies = unpack_dir / "assemblies"
    if assemblies.exists():
        dlls = list(assemblies.glob("*.dll"))
        if dlls:
            xamarin_markers = ["Xamarin", "Mono.Android", "Mono.iOS", "System.Runtime"]
            for dll in dlls:
                if any(m in dll.name for m in xamarin_markers):
                    return DetectedFramework(framework="xamarin", details=f"{len(dlls)} assemblies")
            return DetectedFramework(framework="xamarin", confidence=0.7,
                                     details=f"{len(dlls)} assemblies (no Xamarin marker)")

    # assemblies.blob (compressed)
    blob = unpack_dir / "assemblies" / "assemblies.blob"
    if not blob.exists():
        blob = unpack_dir / "assemblies.blob"
    if blob.exists():
        return DetectedFramework(framework="xamarin", variant="blob",
                                 details="Compressed assemblies.blob")

    return None


def _check_webview_framework(unpack_dir: Path) -> DetectedFramework | None:
    # Cordova/Ionic
    www = unpack_dir / "assets" / "www"
    if www.exists() and (www / "index.html").exists():
        index = (www / "index.html").read_text(errors="replace")
        if "cordova.js" in index or "cordova.min.js" in index:
            return DetectedFramework(framework="cordova")
        if "ionic" in index.lower():
            return DetectedFramework(framework="ionic")
        return DetectedFramework(framework="cordova", confidence=0.7,
                                 details="www/index.html without cordova.js marker")

    # Capacitor
    public = unpack_dir / "assets" / "public"
    if public.exists() and (public / "index.html").exists():
        return DetectedFramework(framework="capacitor")

    return None
