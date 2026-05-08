"""Unit tests for the suspicious-import scoring buckets."""
import pytest

from chimera.parsers.import_scoring import (
    SUSPICIOUS_IMPORTS, BUCKET_WEIGHTS, score_imports,
)


def _imp(dll: str, name: str) -> dict:
    return {"dll": dll, "name": name, "address": None, "ordinal": None}


def test_score_imports_empty_returns_empty():
    assert score_imports([]) == {}


def test_score_imports_process_injection_bucket():
    imports = [
        _imp("kernel32.dll", "VirtualAllocEx"),
        _imp("kernel32.dll", "WriteProcessMemory"),
        _imp("kernel32.dll", "CreateRemoteThread"),
        _imp("user32.dll", "MessageBoxA"),  # not in any bucket
    ]
    out = score_imports(imports)
    assert "process_injection" in out
    assert out["process_injection"]["score"] == 3
    assert "VirtualAllocEx" in out["process_injection"]["imports"]
    assert out["process_injection"]["weight"] == BUCKET_WEIGHTS["process_injection"]


def test_score_imports_multi_bucket():
    imports = [
        _imp("kernel32.dll", "IsDebuggerPresent"),     # anti_debug
        _imp("ws2_32.dll", "socket"),                   # network
        _imp("ws2_32.dll", "connect"),                  # network
        _imp("advapi32.dll", "CryptEncrypt"),           # crypto
    ]
    out = score_imports(imports)
    assert out.get("anti_debug", {}).get("score") == 1
    assert out.get("network", {}).get("score") == 2
    assert out.get("crypto", {}).get("score") == 1


def test_score_imports_mutates_bucket_field():
    imports = [_imp("kernel32.dll", "VirtualAllocEx")]
    score_imports(imports)
    assert imports[0]["bucket"] == "process_injection"


def test_score_imports_unknown_imports_get_no_bucket():
    imports = [_imp("kernel32.dll", "ExitProcess"),
               _imp("user32.dll", "MessageBoxA")]
    out = score_imports(imports)
    assert out == {}
    assert imports[0].get("bucket") in (None, "")


def test_buckets_present():
    expected = {"process_injection", "anti_debug", "persistence",
                "network", "crypto", "filesystem", "evasion"}
    assert expected.issubset(set(SUSPICIOUS_IMPORTS.keys()))
    assert expected.issubset(set(BUCKET_WEIGHTS.keys()))


def test_bucket_weights_are_positive_floats():
    for k, v in BUCKET_WEIGHTS.items():
        assert isinstance(v, (int, float))
        assert v > 0
