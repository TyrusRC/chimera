"""When jadx_sources is None, the dynamic JNI recovery block must still execute.

Regression test for review finding A10. `None.exists()` would raise
AttributeError before this fix, swallowed by the surrounding try/except.
"""
from __future__ import annotations

from pathlib import Path


def test_jadx_sources_check_handles_none():
    """jadx_sources may be None; .exists() must not be called on None."""
    from chimera.pipelines.android import _jadx_sources_available
    assert _jadx_sources_available(None) is False

    real = Path(__file__)
    assert _jadx_sources_available(real) is True

    fake = Path("/no/such/path/xyzzy")
    assert _jadx_sources_available(fake) is False
