"""High-level scan orchestration using the YARA adapter.

Translates raw rule hits into the analyst-facing categories chimera
exposes (`crypto_algorithms`, `commercial_packer`, `obfuscation_techniques`)
plus typed `Findings`-style records the report and CLI surfaces consume.
"""

from __future__ import annotations

import logging
from pathlib import Path

from chimera.adapters.yara_adapter import YaraAdapter

logger = logging.getLogger(__name__)


_FILENAME_PACKER_HINTS: list[tuple[str, str]] = [
    ("libsecexe.so", "Bangcle"),
    ("libsecmain.so", "Bangcle"),
    ("libexec.so", "Ijiami"),
    ("libexecmain.so", "Ijiami"),
    ("libprotectClass.so", "Qihoo360"),
    ("libshella", "Tencent Legu"),
    ("libshellx", "Tencent Legu"),
    ("libjiagu.so", "JiAGu"),
    ("libjiagu_64.so", "JiAGu"),
    ("libshield.so", "Promon SHIELD"),
    ("libloader.appdome", "Appdome"),
    ("libdexprotector", "DexProtector"),
    ("libtalsec", "Talsec freeRASP"),
]


async def scan_native_lib(
    lib_path: Path,
    *,
    adapter: YaraAdapter | None = None,
    extra_rules_dir: Path | None = None,
) -> dict:
    """Scan one `.so`/`.dylib` and return categorized hits.

    Returns dict with:
      crypto_algorithms: list[str]   — distinct algorithm names
      commercial_packer: str | None  — first packer match, if any
      yara_hits: list[dict]          — raw rule-level detail
    """
    lib_path = Path(lib_path)
    crypto_algos: set[str] = set()
    commercial_packer: str | None = None
    raw_hits: list[dict] = []

    # Filename-level packer hint runs even if YARA isn't installed.
    for needle, packer in _FILENAME_PACKER_HINTS:
        if needle in lib_path.name:
            commercial_packer = packer
            break

    adapter = adapter or YaraAdapter(extra_rules_dir=extra_rules_dir)
    if adapter.is_available():
        result = await adapter.analyze(str(lib_path), {})
        for hit in result.get("hits", []):
            raw_hits.append(hit)
            meta = hit.get("meta") or {}
            kind = meta.get("kind", "")
            if kind == "crypto_constant":
                algo = meta.get("algorithm") or hit["rule"]
                crypto_algos.add(algo)
            elif kind == "commercial_packer" and not commercial_packer:
                commercial_packer = meta.get("packer") or hit["rule"]
    else:
        logger.debug("yara-python not available — using filename-only packer hints")

    return {
        "crypto_algorithms": sorted(crypto_algos),
        "commercial_packer": commercial_packer,
        "yara_hits": raw_hits,
    }
