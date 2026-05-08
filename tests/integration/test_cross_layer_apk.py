"""End-to-end cross-layer test against a fixture APK with one external
Kotlin method bound statically.

Skips when r2/jadx are not on PATH so the suite still runs in lean
environments. Mirrors the existing `test_objc_callsite_extraction_e2e.py`
style.
"""
from pathlib import Path
import shutil

import pytest

FIXTURE = Path(__file__).parent.parent / "fixtures" / "cross_layer" / "sample.apk"


@pytest.mark.skipif(
    not FIXTURE.exists(),
    reason="cross-layer fixture APK not present",
)
@pytest.mark.skipif(
    shutil.which("r2") is None,
    reason="radare2 not available",
)
@pytest.mark.skipif(
    shutil.which("jadx") is None,
    reason="jadx not available",
)
def test_cross_layer_links_one_static_jni_edge(tmp_path):
    import asyncio
    from chimera.core.config import ChimeraConfig
    from chimera.core.engine import ChimeraEngine

    config = ChimeraConfig(
        project_dir=tmp_path / "proj",
        cache_dir=tmp_path / "cache",
    )
    engine = ChimeraEngine(config)
    try:
        model = asyncio.run(engine.analyze(str(FIXTURE)))
    finally:
        asyncio.run(engine.cleanup())

    natives = [f for f in model.functions
               if f.layer == "jvm" and f.metadata and f.metadata.get("is_native")]
    assert len(natives) >= 1

    found_edge = False
    for f in natives:
        for c in model.get_callees(f.address):
            if c.address.startswith("0x") or "::0x" in c.address:
                found_edge = True
                break
    assert found_edge, "expected at least one jni-static edge from a native method"
