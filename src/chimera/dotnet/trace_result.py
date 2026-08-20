"""Parsed result of a `dotnet.tracer` run, and the ways to read a key out of it.

Kept apart from the tracer orchestration because the CLI and the MCP handler
both consume this model without caring how the harness was built or run: they
ask it for the byte[]/string values a hook saw, or for the int/char stream a
VM memory primitive moved.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class TraceResult:
    available: bool
    calls: list[dict] = field(default_factory=list)
    hooks_installed: int = 0
    error: str | None = None

    def byte_values(self) -> list[tuple[str, str, str]]:
        """Every byte[] seen, as (method, ascii, hex) — the useful payloads."""
        out = []
        for c in self.calls:
            for val in (c.get("result"), *c.get("args", [])):
                if isinstance(val, dict) and val.get("type") == "byte[]":
                    out.append((c.get("method", "?"), val.get("ascii", ""),
                                val.get("hex", "")))
        return out

    def strings_seen(self) -> list[tuple[str, str]]:
        """Every string argument/return, as (method, value)."""
        out = []
        for c in self.calls:
            for val in (c.get("result"), *c.get("args", [])):
                if isinstance(val, dict) and val.get("type") == "string":
                    out.append((c.get("method", "?"), val.get("value", "")))
        return out

    def numeric_streams(self) -> dict[str, dict[str, list[int]]]:
        """Per-method int/char values, split into ``return`` and ``args``.

        A bytecode VM shuffles the bytes it compares through memory
        read/write primitives; hooking one and reading this stream is what
        recovers a key the VM never materializes as a managed string. The
        return channel is usually the clean one — a memory-read primitive
        returns one key byte per call, while its args carry loop constants —
        so the two are kept apart rather than interleaved.
        """
        out: dict[str, dict[str, list[int]]] = {}

        def _num(val):
            if not isinstance(val, dict):
                return None
            if val.get("type") == "int":
                return int(val.get("value", 0))
            if val.get("type") == "char":
                return int(val.get("code", 0))
            return None

        def _slot(method):
            return out.setdefault(method, {"return": [], "args": []})

        for c in self.calls:
            method = c.get("method", "?")
            rv = _num(c.get("result"))
            if rv is not None:
                _slot(method)["return"].append(rv)
            for a in c.get("args", []):
                av = _num(a)
                if av is not None:
                    _slot(method)["args"].append(av)
        return out

    @staticmethod
    def reconstruct_ascii(values: list[int]) -> str:
        """Render an int stream as printable ASCII, non-printables as '.'.

        The stream often interleaves a marker with each real byte (e.g.
        0, 'N', 'N'); the dots make that structure legible rather than
        hiding it, so the analyst reads the key straight off the line.
        """
        return "".join(chr(v) if 32 <= v < 127 else "." for v in values)


def parse_trace(trace_out) -> "TraceResult":
    """Read the harness's JSONL trace file into a TraceResult.

    Tolerant by design: the file is appended line-by-line by a separate
    process and a run may be killed mid-write, so a truncated final line is
    skipped rather than fatal.
    """
    import json
    import logging
    from pathlib import Path

    logger = logging.getLogger(__name__)
    trace_out = Path(trace_out)
    result = TraceResult(available=True)
    if not trace_out.exists():
        result.error = "harness produced no trace"
        return result
    for line in trace_out.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        event = rec.get("event")
        if event == "call":
            result.calls.append(rec)
        elif event == "hooks_installed":
            result.hooks_installed = rec.get("count", 0)
        elif event == "entrypoint_threw":
            # Not fatal — a wrong input path often throws after the hook fired.
            logger.debug("entrypoint threw: %s", rec.get("error"))
    return result
