"""Recover original source files from a JavaScript source map.

A production web bundle (webpack/vite/rollup) ships minified, but a `.map` with
`sourcesContent` embeds the *original* source tree — the real logic a CTF/audit
target hides behind minification. This carves that tree back out from a `.map`
file directly, or from a bundle's `//# sourceMappingURL=` (inline `data:` or an
adjacent `.map`). General-purpose (any web bundle); the React Native pipeline has
its own bundle-specific path. Read-only; source paths are sanitised so writing
them out can never escape the output directory.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from pathlib import Path

_SMURL = re.compile(rb"//[#@]\s*sourceMappingURL=(\S+)")


def _safe_rel(src: str) -> str:
    """Turn a source-map `sources` entry into a safe relative path.

    Strips scheme prefixes (`webpack:///`, `file://`, …), drops any `..`
    components and leading slashes, so the result can be joined under an output
    dir without traversal.
    """
    s = re.sub(r"^[a-zA-Z][\w.+-]*://+", "", src)   # webpack:/// , file:// , …
    s = s.lstrip("/")
    parts = [p for p in s.split("/") if p not in ("", ".", "..")]
    return "/".join(parts) or "unnamed"


def _load_map_for_bundle(bundle: Path) -> dict | None:
    data = bundle.read_bytes()
    m = _SMURL.search(data)
    if m:
        url = m.group(1).decode(errors="replace")
        if url.startswith("data:"):
            try:
                b64 = url.split(",", 1)[1]
                return json.loads(base64.b64decode(b64))
            except (IndexError, binascii.Error, ValueError):
                return None
        cand = bundle.parent / url
        if cand.exists():
            return json.loads(cand.read_text())
    cand = bundle.with_name(bundle.name + ".map")
    return json.loads(cand.read_text()) if cand.exists() else None


def recover_sources(path: str) -> dict:
    p = Path(path)
    try:
        if p.suffix == ".map":
            data = json.loads(p.read_text())
        else:
            data = _load_map_for_bundle(p)
    except (OSError, ValueError) as e:
        return {"ok": False, "error": f"could not read source map: {e}"}
    if data is None:
        return {"ok": False,
                "error": "no source map found (no sourceMappingURL and no adjacent .map)"}

    sources = data.get("sources") or []
    contents = data.get("sourcesContent") or []
    files: dict[str, str] = {}
    missing = []
    for i, src in enumerate(sources):
        if i < len(contents) and contents[i] is not None:
            files[_safe_rel(str(src))] = contents[i]
        else:
            missing.append(str(src))
    return {"ok": True, "count": len(files), "files": files, "missing_content": missing}


def write_sources(recovered: dict, out_dir: str) -> list[str]:
    """Write recovered `files` under out_dir (paths already sanitised). Returns paths."""
    out = Path(out_dir)
    written = []
    for rel, content in recovered.get("files", {}).items():
        dst = out / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(content)
        written.append(str(dst))
    return written
