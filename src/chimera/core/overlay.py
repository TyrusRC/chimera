"""Persistent analyst annotations — renames, comments, types.

The overlay sits alongside the analysis cache and survives restarts. It
records the analyst's "n key" decisions: a function renamed in the UI is
remembered next time the same binary is loaded.

File layout::

    <project_dir>/<sha256>/overlay.json

Shape::

    {
      "schema": "chimera-overlay/1",
      "function_names":   { "0x140001000": "decode_license" },
      "variable_renames": { "0x140001000": { "iVar1": "license_byte" } },
      "comments":         { "0x140001000": { "0": "Entry point", "12": "..." } },
      "function_types":   { "0x140001000": "int decode_license(char*)" },
      "user_classifications": { "0x140001000": "crypto" }
    }

Addresses are stored as the canonical hex form `FunctionInfo.address` carries
("0x..." lowercase). Callers should normalise before lookup; `_normalize_addr`
does the right thing on inputs that may arrive as int / "0x..." / "0X..".
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

OVERLAY_SCHEMA = "chimera-overlay/1"


def _normalize_addr(addr: str | int) -> str:
    """Canonicalise to lowercase 0x... so lookup is stable across backends."""
    if isinstance(addr, int):
        return hex(addr)
    s = str(addr).strip().lower()
    if not s.startswith("0x"):
        # Tolerate bare hex / decimal so the API accepts what r2 / ghidra emit.
        try:
            return hex(int(s, 16))
        except ValueError:
            try:
                return hex(int(s, 10))
            except ValueError:
                return s
    try:
        return hex(int(s, 16))
    except ValueError:
        return s


@dataclass
class ProjectOverlay:
    """Per-binary annotation overlay. All maps are keyed by function address."""

    sha256: str
    function_names: dict[str, str] = field(default_factory=dict)
    variable_renames: dict[str, dict[str, str]] = field(default_factory=dict)
    comments: dict[str, dict[str, str]] = field(default_factory=dict)
    function_types: dict[str, str] = field(default_factory=dict)
    user_classifications: dict[str, str] = field(default_factory=dict)
    # Notebook entries — narrative findings keyed by UUID. Each value carries
    # {"id", "title", "body", "tags": [...], "evidence": [...], "created_at",
    # "updated_at"}. Evidence items are {"address": "0x..", "line": int}.
    notes: dict[str, dict] = field(default_factory=dict)
    _path: Optional[Path] = None
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    # ----- I/O -----------------------------------------------------------

    @classmethod
    def load(cls, project_dir: Path, sha256: str) -> "ProjectOverlay":
        """Read overlay from disk; return empty overlay if absent."""
        path = cls._overlay_path(project_dir, sha256)
        if not path.exists():
            return cls(sha256=sha256, _path=path)
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("overlay %s unreadable (%s) — starting fresh", path, exc)
            return cls(sha256=sha256, _path=path)
        return cls(
            sha256=sha256,
            function_names=dict(data.get("function_names") or {}),
            variable_renames={
                k: dict(v) for k, v in (data.get("variable_renames") or {}).items()
            },
            comments={
                k: dict(v) for k, v in (data.get("comments") or {}).items()
            },
            function_types=dict(data.get("function_types") or {}),
            user_classifications=dict(data.get("user_classifications") or {}),
            notes={k: dict(v) for k, v in (data.get("notes") or {}).items()},
            _path=path,
        )

    def save(self) -> None:
        """Persist atomically. Caller must have set `_path` (i.e. used `load`)."""
        if self._path is None:
            raise RuntimeError("ProjectOverlay was constructed without a path; cannot save")
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "schema": OVERLAY_SCHEMA,
                "sha256": self.sha256,
                "function_names": self.function_names,
                "variable_renames": self.variable_renames,
                "comments": self.comments,
                "function_types": self.function_types,
                "user_classifications": self.user_classifications,
                "notes": self.notes,
            }
            # Atomic write: same-fs tempfile + rename. A crash mid-write leaves
            # the previous version intact rather than truncating to zero bytes.
            fd, tmp = tempfile.mkstemp(
                prefix=".overlay.", suffix=".json", dir=self._path.parent,
            )
            try:
                with os.fdopen(fd, "w") as fh:
                    json.dump(payload, fh, indent=2)
                os.replace(tmp, self._path)
            except Exception:
                # Clean up the orphan tempfile on any failure.
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise

    @staticmethod
    def _overlay_path(project_dir: Path, sha256: str) -> Path:
        return Path(project_dir) / sha256 / "overlay.json"

    # ----- mutators ------------------------------------------------------

    def rename_function(self, addr: str, new_name: str) -> None:
        with self._lock:
            self.function_names[_normalize_addr(addr)] = new_name

    def rename_variable(self, func_addr: str, original: str, new_name: str) -> None:
        with self._lock:
            self.variable_renames.setdefault(_normalize_addr(func_addr), {})[original] = new_name

    def add_comment(self, func_addr: str, line: str | int, text: str) -> None:
        with self._lock:
            self.comments.setdefault(_normalize_addr(func_addr), {})[str(line)] = text

    def set_function_type(self, addr: str, signature: str) -> None:
        with self._lock:
            self.function_types[_normalize_addr(addr)] = signature

    def set_classification(self, addr: str, classification: str) -> None:
        with self._lock:
            self.user_classifications[_normalize_addr(addr)] = classification

    def delete_function_name(self, addr: str) -> bool:
        with self._lock:
            return self.function_names.pop(_normalize_addr(addr), None) is not None

    def delete_comment(self, func_addr: str, line: str | int) -> bool:
        with self._lock:
            block = self.comments.get(_normalize_addr(func_addr))
            if not block:
                return False
            return block.pop(str(line), None) is not None

    # ----- notebook ------------------------------------------------------

    def add_note(
        self,
        title: str,
        body: str,
        tags: Optional[list[str]] = None,
        evidence: Optional[list[dict]] = None,
    ) -> str:
        """Create a notebook entry and return its UUID.

        Evidence items are normalised so addresses are lowercase 0x...; that
        keeps deep-link references stable regardless of how the caller wrote
        them. Tags are deduplicated while preserving order.
        """
        note_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        norm_tags: list[str] = []
        seen: set[str] = set()
        for t in (tags or []):
            if t and t not in seen:
                seen.add(t)
                norm_tags.append(t)
        norm_evidence: list[dict] = []
        for ev in (evidence or []):
            if not isinstance(ev, dict):
                continue
            addr = ev.get("address")
            if not addr:
                continue
            line = ev.get("line", 0)
            try:
                line_int = int(line)
            except (TypeError, ValueError):
                line_int = 0
            norm_evidence.append({"address": _normalize_addr(addr), "line": line_int})
        entry = {
            "id": note_id,
            "title": title,
            "body": body,
            "tags": norm_tags,
            "evidence": norm_evidence,
            "created_at": now,
            "updated_at": now,
        }
        with self._lock:
            self.notes[note_id] = entry
        return note_id

    def update_note(self, note_id: str, **fields) -> bool:
        """Patch an entry in-place; return False if no such note."""
        with self._lock:
            entry = self.notes.get(note_id)
            if not entry:
                return False
            if "title" in fields and fields["title"] is not None:
                entry["title"] = fields["title"]
            if "body" in fields and fields["body"] is not None:
                entry["body"] = fields["body"]
            if "tags" in fields and fields["tags"] is not None:
                seen: set[str] = set()
                norm: list[str] = []
                for t in fields["tags"]:
                    if t and t not in seen:
                        seen.add(t)
                        norm.append(t)
                entry["tags"] = norm
            if "evidence" in fields and fields["evidence"] is not None:
                norm_evidence: list[dict] = []
                for ev in fields["evidence"]:
                    if not isinstance(ev, dict):
                        continue
                    addr = ev.get("address")
                    if not addr:
                        continue
                    try:
                        line_int = int(ev.get("line", 0))
                    except (TypeError, ValueError):
                        line_int = 0
                    norm_evidence.append({"address": _normalize_addr(addr), "line": line_int})
                entry["evidence"] = norm_evidence
            entry["updated_at"] = datetime.now(timezone.utc).isoformat()
            return True

    def remove_note(self, note_id: str) -> bool:
        with self._lock:
            return self.notes.pop(note_id, None) is not None

    def list_notes(self, tag: Optional[str] = None) -> list[dict]:
        """Return notes (newest first by created_at), optionally tag-filtered."""
        with self._lock:
            entries = list(self.notes.values())
        if tag:
            entries = [e for e in entries if tag in (e.get("tags") or [])]
        entries.sort(key=lambda e: e.get("created_at", ""), reverse=True)
        # Return shallow copies so callers can't mutate our state.
        return [dict(e) for e in entries]

    # ----- accessors -----------------------------------------------------

    def get_function_name(self, addr: str) -> Optional[str]:
        return self.function_names.get(_normalize_addr(addr))

    def get_variable_renames(self, func_addr: str) -> dict[str, str]:
        return dict(self.variable_renames.get(_normalize_addr(func_addr)) or {})

    def get_comments(self, func_addr: str) -> dict[str, str]:
        return dict(self.comments.get(_normalize_addr(func_addr)) or {})

    def get_function_type(self, addr: str) -> Optional[str]:
        return self.function_types.get(_normalize_addr(addr))

    # ----- apply ---------------------------------------------------------

    def apply_to_model(self, model) -> int:
        """Push the overlay's renames + comments + types into the live model.

        Returns the number of FunctionInfo entries touched. Safe to call
        multiple times — later loads always overwrite earlier ones with the
        same key.
        """
        touched = 0
        for f in model.functions:
            user_name = self.get_function_name(f.address)
            if user_name and user_name != f.name:
                f.name = user_name
                touched += 1
            type_sig = self.get_function_type(f.address)
            if type_sig:
                f.signature = type_sig
            user_cls = self.user_classifications.get(_normalize_addr(f.address))
            if user_cls:
                f.classification = user_cls
        return touched
