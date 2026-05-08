"""Function metadata model."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class FunctionInfo:
    address: str
    name: str
    original_name: str
    language: str
    classification: str
    layer: str
    source_backend: str
    decompiled: Optional[str] = None
    signature: Optional[str] = None
    disassembly: Optional[list[dict]] = None
    ai_renamed: bool = False
    ai_comments: Optional[str] = None
    sources: list[str] = field(default_factory=list)
    metadata: Optional[dict] = None


@dataclass
class StringEntry:
    address: str
    value: str
    section: Optional[str] = None
    decrypted_from: Optional[str] = None
    referenced_by: list[str] = field(default_factory=list)


@dataclass
class CallEdge:
    caller_addr: str
    callee_addr: str
    call_type: str


@dataclass
class ImportEntry:
    """A single function/symbol import from another module.

    For PE: `dll` is the importing DLL ("kernel32.dll"). For ELF or
    ordinal-imports: `dll` may be empty. `bucket` is set later by
    `parsers.import_scoring.score_imports` when the symbol matches a
    suspicious-imports bucket.
    """
    dll: str
    name: str
    address: str | None = None
    ordinal: int | None = None
    bucket: str | None = None
