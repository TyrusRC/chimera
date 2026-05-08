"""Unit tests for the YARA rule author."""
from pathlib import Path

import pytest

from chimera.detection_engineering.yara_author import (
    _anchor_for_format, _normalize_rule_name, _pick_imports,
    _yara_quote, author_yara_rule,
)
from chimera.model.binary import (
    Architecture, BinaryFormat, BinaryInfo, Framework, Platform,
)
from chimera.model.function import ImportEntry, StringEntry
from chimera.model.program import UnifiedProgramModel

yara = pytest.importorskip("yara")


def _make_model(fmt: BinaryFormat = BinaryFormat.PE64, *,
                strings: list[str] | None = None,
                imports: list[ImportEntry] | None = None) -> UnifiedProgramModel:
    bi = BinaryInfo(
        sha256="ab" * 32, path=Path("/tmp/x.exe"),
        format=fmt, platform=Platform.WINDOWS,
        arch=Architecture.X86_64, framework=Framework.NATIVE, size_bytes=1,
    )
    m = UnifiedProgramModel(bi)
    for i, value in enumerate(strings or []):
        m.add_string(address=hex(0x1000 + i * 8), value=value, section=".rdata")
    for imp in imports or []:
        m.add_import(imp)
    return m


def test_normalize_rule_name_strips_unsafe_chars():
    assert _normalize_rule_name("foo-bar.baz") == "foo_bar_baz"
    assert _normalize_rule_name("123abc") == "abc"
    assert _normalize_rule_name("") == "Generated_Rule"


def test_yara_quote_simple_ascii():
    assert _yara_quote("hello world") == '"hello world"'


def test_yara_quote_escapes_backslash_and_quote():
    out = _yara_quote('foo "bar" \\baz')
    assert '\\"' in out
    assert "\\\\" in out


def test_anchor_for_pe():
    assert _anchor_for_format(BinaryFormat.PE32) == "uint16(0) == 0x5A4D"
    assert _anchor_for_format(BinaryFormat.PE64) == "uint16(0) == 0x5A4D"
    assert _anchor_for_format(BinaryFormat.DOTNET_PE) == "uint16(0) == 0x5A4D"


def test_anchor_for_elf():
    assert _anchor_for_format(BinaryFormat.ELF_STANDALONE) == "uint32(0) == 0x464C457F"


def test_anchor_for_unknown_format_is_none():
    assert _anchor_for_format(BinaryFormat.HBC) is None


def test_pick_imports_orders_by_bucket_priority():
    m = _make_model(imports=[
        ImportEntry(dll="ws2_32.dll", name="connect", bucket="network"),
        ImportEntry(dll="kernel32.dll", name="VirtualAllocEx", bucket="process_injection"),
        ImportEntry(dll="kernel32.dll", name="IsDebuggerPresent", bucket="anti_debug"),
    ])
    out = _pick_imports(m, max_imports=10)
    names = [n for _, n in out]
    # process_injection > anti_debug > network
    assert names == ["VirtualAllocEx", "IsDebuggerPresent", "connect"]


def test_pick_imports_skips_unscored_imports():
    m = _make_model(imports=[
        ImportEntry(dll="kernel32.dll", name="ExitProcess"),  # no bucket
        ImportEntry(dll="kernel32.dll", name="VirtualAllocEx", bucket="process_injection"),
    ])
    out = _pick_imports(m, max_imports=10)
    names = [n for _, n in out]
    assert names == ["VirtualAllocEx"]


def test_pick_imports_respects_cap():
    imports = [ImportEntry(dll="x.dll", name=f"fn_{i}", bucket="network") for i in range(50)]
    m = _make_model(imports=imports)
    out = _pick_imports(m, max_imports=5)
    assert len(out) == 5


def test_author_yara_rule_emits_well_formed_rule():
    m = _make_model(
        fmt=BinaryFormat.PE64,
        strings=[
            "X-API-Key: 9f8a6c3e2b1d4f0a",
            "https://c2.evil.example.com/upload",
            "kernel32.dll",  # filtered by denylist
            "Mozilla/5.0 (Windows NT 10.0)",
        ],
        imports=[
            ImportEntry(dll="kernel32.dll", name="VirtualAllocEx", bucket="process_injection"),
        ],
    )
    rule = author_yara_rule(m)
    assert "rule Chimera_" in rule
    assert "uint16(0) == 0x5A4D" in rule
    assert "X-API-Key" in rule
    # The denylisted string is dropped
    assert "$s" in rule and "kernel32.dll" not in rule.split("strings:")[1].split("condition:")[0]


def test_author_yara_rule_compiles_with_yara():
    m = _make_model(
        fmt=BinaryFormat.PE64,
        strings=[
            "uniqueXyzString12345",
            "http://malicious.example.test/c2",
            "MyMalwareFamily-2026",
        ],
        imports=[
            ImportEntry(dll="kernel32.dll", name="VirtualAllocEx", bucket="process_injection"),
            ImportEntry(dll="ws2_32.dll", name="connect", bucket="network"),
        ],
    )
    rule = author_yara_rule(m, rule_name="TestRule", family="TestFamily")
    # Round-trip through YARA's compiler
    compiled = yara.compile(source=rule)
    assert compiled is not None


def test_author_yara_rule_with_no_signals_emits_unmatchable():
    m = _make_model(fmt=BinaryFormat.PE64, strings=[], imports=[])
    rule = author_yara_rule(m)
    assert "false" in rule  # falls back to unmatchable rule
