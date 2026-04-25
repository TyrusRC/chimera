"""React Native sub-pipeline — bundle discovery, source-map parsing, decompile orchestration."""

from __future__ import annotations

from pathlib import Path


def find_rn_bundle(unpack_dir: Path, platform: str) -> Path | None:
    """Locate a React Native JavaScript bundle in an unpacked APK or IPA.

    Android priority: assets/index.android.bundle, assets/index.bundle.
    iOS priority: main.jsbundle, then any *.jsbundle under unpack_dir.

    Returns first existing path or None. Never raises.
    """
    unpack_dir = Path(unpack_dir)
    if platform == "android":
        for rel in ("assets/index.android.bundle", "assets/index.bundle"):
            candidate = unpack_dir / rel
            if candidate.is_file():
                return candidate
        return None
    if platform == "ios":
        main = unpack_dir / "main.jsbundle"
        if main.is_file():
            return main
        for candidate in sorted(unpack_dir.glob("*.jsbundle")):
            if candidate.is_file():
                return candidate
        return None
    return None


def find_source_map(bundle_path: Path) -> Path | None:
    """Locate a sibling source map file next to a JS bundle.

    Priority:
      1. <bundle>.map (e.g. index.android.bundle.map)
      2. <bundle.parent>/<bundle.stem>.map (e.g. main.map for main.jsbundle)

    Returns first existing path or None. Never raises.
    """
    bundle_path = Path(bundle_path)
    candidates = [
        bundle_path.with_suffix(bundle_path.suffix + ".map"),
        bundle_path.parent / (bundle_path.stem + ".map"),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None
