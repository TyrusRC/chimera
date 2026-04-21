"""Asserts every EXPECTED_MATRIX pair has at least one registered test."""
from __future__ import annotations

from tests.deobf_evidence._registry import EXPECTED_MATRIX, REGISTERED


def test_all_expected_pairs_registered():
    # Import the per-tool test modules so @register_evidence decorators fire.
    import tests.deobf_evidence.test_bypass_evidence  # noqa: F401
    import tests.deobf_evidence.test_core_adapter_evidence  # noqa: F401
    import tests.deobf_evidence.test_cross_platform_evidence  # noqa: F401
    import tests.deobf_evidence.test_missing_tools_evidence  # noqa: F401

    missing = EXPECTED_MATRIX - REGISTERED
    assert not missing, f"Missing evidence tests: {sorted(missing)}"
