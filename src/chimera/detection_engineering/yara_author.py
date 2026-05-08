"""Author a draft YARA rule from an analyzed UnifiedProgramModel.

Picks high-fitness strings via `string_scorer`, pulls suspicious imports
from `model.imports` (when imports were scored into buckets), and emits
a YARA rule with a magic-byte anchor and an `N of` condition.

Output is a *draft* — analysts are expected to review, prune, and tune
thresholds before deploying. The author is conservative: it prefers to
include too few signals rather than too many low-quality ones.
"""
from __future__ import annotations

import datetime
import re
from dataclasses import dataclass
from typing import Optional

from chimera.detection_engineering.string_scorer import score_strings
from chimera.model.binary import BinaryFormat
from chimera.model.program import UnifiedProgramModel


# Bucket priority order — process_injection is the loudest tell;
# filesystem is essentially noise on its own.
_BUCKET_ORDER = (
    "process_injection",
    "anti_debug",
    "persistence",
    "evasion",
    "crypto",
    "network",
    "filesystem",
)

_RULE_NAME_SAFE = re.compile(r"[^A-Za-z0-9_]")


@dataclass
class YaraRuleDraft:
    """Structured form of the rule, before serialization."""
    rule_name: str
    sha256: str
    family: Optional[str]
    string_entries: list[tuple[str, str, list[str]]]  # (id, value, modifiers)
    import_entries: list[tuple[str, str]]              # (id, name)
    anchor: Optional[str]                              # uint16(0) == 0x... etc
    min_string_matches: int

    def render(self) -> str:
        lines: list[str] = []
        lines.append(f"rule {self.rule_name}")
        lines.append("{")
        lines.append("    meta:")
        lines.append('        author = "chimera-yara-author"')
        lines.append(f'        sha256 = "{self.sha256}"')
        if self.family:
            lines.append(f'        family = "{self.family}"')
        lines.append(f'        generated = "{datetime.date.today().isoformat()}"')
        lines.append("")
        if self.string_entries or self.import_entries:
            lines.append("    strings:")
            for sid, value, modifiers in self.string_entries:
                mods = " " + " ".join(modifiers) if modifiers else ""
                lines.append(f"        ${sid} = {_yara_quote(value)}{mods}")
            for sid, name in self.import_entries:
                lines.append(f'        ${sid} = "{name}" ascii')
            lines.append("")
        lines.append("    condition:")
        condition_parts: list[str] = []
        body = self._condition_body()
        if body:
            condition_parts.append(body)
            # Only add anchor when we have signals
            if self.anchor:
                condition_parts.append(self.anchor)
        if not condition_parts:
            condition_parts = ["false  // no signals — rebuild after analysis"]
        lines.append("        " + " and\n        ".join(condition_parts))
        lines.append("}")
        return "\n".join(lines) + "\n"

    def _condition_body(self) -> str:
        sig_count = len(self.string_entries) + len(self.import_entries)
        if sig_count == 0:
            return ""
        n = min(self.min_string_matches, sig_count)
        return f"{n} of (${'*'})"


def _yara_quote(value: str) -> str:
    """Render a string literal safely for YARA. Escape backslashes,
    quotes, and non-printable chars with hex escapes.

    Falls back to a hex string `{...}` when the value has many
    non-printable bytes — but in practice we only get printable ASCII
    out of the model, so this branch is rare.
    """
    needs_hex = sum(1 for c in value if not (32 <= ord(c) < 127)) > len(value) * 0.2
    if needs_hex:
        hex_str = " ".join(f"{ord(c):02X}" for c in value)
        return "{ " + hex_str + " }"
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    # Replace non-printable single chars with \xHH
    out_chars: list[str] = []
    for c in escaped:
        if 32 <= ord(c) < 127:
            out_chars.append(c)
        elif c == "\\":
            out_chars.append("\\\\")
        elif c == "\n":
            out_chars.append("\\n")
        elif c == "\t":
            out_chars.append("\\t")
        else:
            out_chars.append(f"\\x{ord(c):02X}")
    return '"' + "".join(out_chars) + '"'


def _normalize_rule_name(raw: str) -> str:
    cleaned = _RULE_NAME_SAFE.sub("_", raw)
    cleaned = cleaned.lstrip("_0123456789")  # YARA rules can't start with digit
    return cleaned or "Generated_Rule"


def _anchor_for_format(fmt: BinaryFormat) -> Optional[str]:
    """Return a YARA condition fragment that anchors on file type."""
    pe_family = {
        BinaryFormat.PE, BinaryFormat.PE32, BinaryFormat.PE64,
        BinaryFormat.DOTNET_PE, BinaryFormat.DLL,
    }
    if fmt in pe_family:
        return "uint16(0) == 0x5A4D"  # MZ
    elf_family = {BinaryFormat.ELF, BinaryFormat.ELF_STANDALONE}
    if fmt in elf_family:
        return "uint32(0) == 0x464C457F"  # 0x7F 'E' 'L' 'F' little-endian
    if fmt == BinaryFormat.MACHO:
        # Either MH_MAGIC_64 or its byte-swapped little-endian form
        return "(uint32(0) == 0xFEEDFACF or uint32(0) == 0xCFFAEDFE)"
    if fmt == BinaryFormat.DEX:
        return "uint32(0) == 0x0A786564"  # "dex\\n"
    if fmt in {BinaryFormat.APK, BinaryFormat.AAB, BinaryFormat.IPA, BinaryFormat.XAPK}:
        return "uint32(0) == 0x04034B50"  # PK\\x03\\x04
    return None


def _pick_imports(model: UnifiedProgramModel, max_imports: int) -> list[tuple[str, str]]:
    """Return [(yara_id, import_name), ...] for the top scored imports."""
    candidates: list[tuple[str, str]] = []
    seen: set[str] = set()
    # First pass: imports with a `bucket` annotation, ordered by bucket priority
    bucket_groups: dict[str, list[str]] = {}
    for imp in model.imports:
        if imp.bucket:
            bucket_groups.setdefault(imp.bucket, []).append(imp.name)
    for b in _BUCKET_ORDER:
        for name in bucket_groups.get(b, []):
            if name and name not in seen and len(name) >= 3:
                seen.add(name)
                yara_id = "imp_" + _RULE_NAME_SAFE.sub("_", name)[:32]
                candidates.append((yara_id, name))
                if len(candidates) >= max_imports:
                    return candidates
    return candidates


def author_yara_rule(
    model: UnifiedProgramModel,
    *,
    rule_name: Optional[str] = None,
    family: Optional[str] = None,
    max_strings: int = 12,
    max_imports: int = 10,
    min_string_length: int = 8,
    min_string_matches: int = 4,
) -> str:
    """Generate a draft YARA rule string from an analyzed model.

    Caller is expected to write the result to a `.yar` file or print it.
    """
    raw_name = rule_name or f"Chimera_{model.binary.sha256[:12]}"
    final_rule_name = _normalize_rule_name(raw_name)

    # Strings — pull from model.get_strings(), score, take top max_strings
    raw_values = []
    try:
        for s in model.get_strings():
            v = getattr(s, "value", None) or (s.get("value") if isinstance(s, dict) else None)
            if isinstance(v, str):
                raw_values.append(v)
    except Exception:
        pass
    scored = score_strings(raw_values, min_length=min_string_length, max_results=max_strings)
    string_entries: list[tuple[str, str, list[str]]] = []
    for i, (value, _score) in enumerate(scored, start=1):
        # Default modifiers: ascii. Add `wide` if the value looks like
        # it'd plausibly appear UTF-16-encoded too (heuristic: heavy
        # ASCII content, no spaces — typical of API names / paths).
        mods = ["ascii"]
        if value.count(" ") <= len(value) // 8 and len(value) <= 40:
            mods.append("wide")
        string_entries.append((f"s{i}", value, mods))

    import_entries = _pick_imports(model, max_imports)

    anchor = _anchor_for_format(model.binary.format)

    draft = YaraRuleDraft(
        rule_name=final_rule_name,
        sha256=model.binary.sha256,
        family=family,
        string_entries=string_entries,
        import_entries=import_entries,
        anchor=anchor,
        min_string_matches=min_string_matches,
    )
    return draft.render()
