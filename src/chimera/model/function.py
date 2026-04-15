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
