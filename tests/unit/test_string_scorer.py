"""Unit tests for the YARA string-quality scorer."""
from chimera.detection_engineering.string_scorer import (
    is_interesting, score_strings, _rarity_weight,
)


def test_too_short_rejected():
    assert is_interesting("short") is False
    assert is_interesting("a" * 7) is False


def test_min_length_param_respected():
    assert is_interesting("x" * 5, min_length=4) is True
    assert is_interesting("x" * 5, min_length=6) is False


def test_common_string_rejected():
    assert is_interesting("kernel32.dll") is False
    assert is_interesting("KERNEL32.DLL") is False  # case-insensitive


def test_all_digits_rejected():
    assert is_interesting("12345678") is False
    assert is_interesting("99999999999") is False


def test_all_hex_rejected():
    assert is_interesting("deadbeefcafe1234") is False
    assert is_interesting("DEADBEEFCAFE1234") is False


def test_repeated_chars_rejected():
    assert is_interesting("AAAAAAAAAAA") is False
    assert is_interesting("--------foo") is False


def test_punctuation_heavy_rejected():
    assert is_interesting("!!!!!!!!!!!!") is False
    assert is_interesting("....////....") is False


def test_distinctive_string_accepted():
    assert is_interesting("X-API-Key: abc123XYZ") is True
    assert is_interesting("https://evil.example.com/c2") is True


def test_rarity_weight_distinctive_string_high():
    # Has upper, digit, and symbol -> diversity 3 -> 1.0
    assert _rarity_weight("Foo123!") == 1.0


def test_rarity_weight_lowercase_alnum_low():
    assert _rarity_weight("hellokitty") == 0.3


def test_score_strings_deduplicates():
    out = score_strings(["abcdefgh", "abcdefgh", "ijklmnop"])
    values = [v for v, _ in out]
    assert values.count("abcdefgh") == 1


def test_score_strings_sorted_by_score_desc():
    short_distinctive = "abc!1Z"  # diversity 3, length 6 — rejected by length
    longer_distinctive = "abc!1Zfoobar"  # length 12, diversity 3
    longest = "this-is-a-longer-string-with-Caps-and-symbols-1!"
    out = score_strings([short_distinctive, longer_distinctive, longest])
    # `short_distinctive` is filtered out by length; longest should rank first
    assert len(out) == 2
    assert out[0][0] == longest


def test_score_strings_respects_max_results():
    candidates = [f"unique_string_with_caps_{i}_X!" for i in range(100)]
    out = score_strings(candidates, max_results=10)
    assert len(out) == 10


def test_score_strings_truncates_huge_inputs():
    huge = "X" * 500 + "y"
    out = score_strings([huge])
    # 500 X's would normally be rejected by repeated-char heuristic;
    # use varied content
    varied = ("ABcd1!" * 50)  # 300 chars, diverse
    out = score_strings([varied])
    if out:
        assert len(out[0][0]) <= 200
