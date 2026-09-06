"""Peel a layered / marshalled Python blob — statically, never executing it.

A common way to hide Python is to wrap a marshalled code object in a stack
of transforms — `exec(marshal.loads(zlib.decompress(BLOB)))` is the classic,
often nested several deep with base85/base64 and bz2/lzma between the layers,
and the innermost code compiled for a *different* Python than the host.

Running such a blob is a trap: it may be keyed, sandbox-hostile, or simply
never reach the interesting path. So this unwraps it the safe way — pull the
bytes literal out of the `.py` with `ast.literal_eval` (never import/exec the
module), then recursively detect and undo each transform in memory.

The payoff is the **version-independent** view: `co_names`, `co_consts`,
`co_varnames`, and `co_filename` marshal cleanly even when the bytecode was
compiled for another interpreter (so `dis` would show garbage), and they
already reveal the imports, embedded keys/strings, and call sequence. That
tree is dumped for every code object found. Cross-version *opcode*
disassembly is available separately (`disassemble`) for when you need it.

Pure stdlib, read-only, in-memory: it returns the layer tree and never
executes the target or writes files.
"""
from __future__ import annotations

import ast
import base64
import binascii
import bz2
import gzip
import logging
import lzma
import marshal
import types
import zlib
from dataclasses import dataclass, field
from pathlib import Path

from chimera.unpacking.pymagic import detect_pyc_version

logger = logging.getLogger(__name__)

# Resource guards against a zip-bomb / runaway recursion. A caller can raise
# max_depth; the size cap is fixed because it protects the process, not the
# analysis. NOTE: a 64 MiB total decompression ceiling — bump _MAX_TOTAL if a
# legitimately huge payload is ever truncated.
_MAX_TOTAL = 64 * 1024 * 1024
_CONST_REPR_CAP = 80           # per-const repr length in a co_consts summary

# marshal type byte for a code object: 'c' (0x63), or with the FLAG_REF bit
# (0x80) set -> 0xE3, which is what CPython emits for a top-level code object.
_MARSHAL_CODE = {0x63, 0xE3}


@dataclass
class LayerNode:
    """One node in the unwrap tree.

    `kind` is the transform this node represents:
    'pyliteral' (a bytes/str literal lifted from a .py), 'zlib' / 'gzip' /
    'bz2' / 'lzma' (a decompression), 'base64' / 'base85' (a decode),
    'marshal' (a marshalled code object — the code fields below are filled),
    or 'raw' (an opaque leaf we could not peel further).

    For a 'marshal' code node the code-object fields are populated and
    `children` holds any nested code objects (functions/comprehensions) found
    in its consts; for a wrapper node `children` holds the single next layer.
    """
    kind: str
    detail: str | None = None
    # code-object fields — populated only when kind == 'marshal'
    name: str | None = None
    co_names: tuple[str, ...] | None = None
    co_consts_summary: list[str] | None = None
    co_varnames: tuple[str, ...] | None = None
    co_filename: str | None = None
    co_flags: int | None = None
    argcount: int | None = None
    children: list[LayerNode] = field(default_factory=list)
    # The recovered code object itself, kept for `disassemble`; inert data,
    # never executed, and excluded from the serialized tree.
    code_obj: types.CodeType | None = field(default=None, repr=False, compare=False)

    def walk(self):
        """Yield this node and every descendant, depth-first."""
        yield self
        for child in self.children:
            yield from child.walk()

    def to_dict(self) -> dict:
        d: dict = {"kind": self.kind}
        if self.detail is not None:
            d["detail"] = self.detail
        if self.co_names is not None:              # a code node
            d["name"] = self.name
            d["co_filename"] = self.co_filename
            d["co_flags"] = self.co_flags
            d["argcount"] = self.argcount
            d["co_names"] = list(self.co_names)
            d["co_varnames"] = list(self.co_varnames or ())
            d["co_consts_summary"] = self.co_consts_summary or []
        if self.children:
            d["children"] = [c.to_dict() for c in self.children]
        return d


@dataclass
class UnwrapResult:
    source: str
    root: LayerNode | None = None
    python_version: int | None = None
    truncated: bool = False
    error: str | None = None

    def iter_nodes(self):
        if self.root is not None:
            yield from self.root.walk()

    def code_nodes(self) -> list[LayerNode]:
        """Every marshalled code object in the tree, outermost first."""
        return [n for n in self.iter_nodes() if n.kind == "marshal"]

    def deepest_code(self) -> LayerNode | None:
        """The most deeply nested code node — usually the real payload."""
        deepest, best = None, -1

        def rec(node: LayerNode, depth: int):
            nonlocal deepest, best
            if node.kind == "marshal" and depth > best:
                deepest, best = node, depth
            for c in node.children:
                rec(c, depth + 1)

        if self.root is not None:
            rec(self.root, 0)
        return deepest

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "python_version": self.python_version,
            "truncated": self.truncated,
            "error": self.error,
            "tree": self.root.to_dict() if self.root else None,
        }


class _Budget:
    """Tracks remaining decompression budget and the depth ceiling."""

    def __init__(self, max_depth: int):
        self.max_depth = max_depth
        self.remaining = _MAX_TOTAL
        self.truncated = False

    def spend(self, n: int) -> bool:
        """Charge `n` bytes; return False (and latch truncated) if over budget."""
        if n > self.remaining:
            self.truncated = True
            return False
        self.remaining -= n
        return True


# ── low-level detectors ────────────────────────────────────────────────────

def _looks_marshalled(data: bytes) -> bool:
    return len(data) >= 1 and data[0] in _MARSHAL_CODE


def _is_ascii_ish(data: bytes) -> bool:
    """True for a buffer that is plausibly a base64/base85 text blob."""
    if not data:
        return False
    return all(0x20 <= b < 0x7F or b in (9, 10, 13) for b in data)


def _sniff_peelable(data: bytes) -> bool:
    """Cheap header check: does `data` look like a further layer worth peeling?"""
    if _looks_marshalled(data):
        return True
    return _decompress_kind(data) is not None


def _decompress_kind(data: bytes) -> str | None:
    """The compression kind `data`'s header advertises, or None."""
    if len(data) >= 2 and data[0] == 0x78:                 # zlib
        return "zlib"
    if data[:2] == b"\x1f\x8b":                             # gzip
        return "gzip"
    if data[:3] == b"BZh":                                  # bz2
        return "bz2"
    if data[:6] == b"\xfd7zXZ\x00" or data[:3] == b"\x5d\x00\x00":   # xz / lzma
        return "lzma"
    return None


def _try_decompress(data: bytes) -> tuple[str, bytes] | None:
    """Decompress `data` by its header. Returns (kind, output) or None."""
    kind = _decompress_kind(data)
    if kind is None:
        return None
    try:
        if kind == "zlib":
            out = zlib.decompress(data)
        elif kind == "gzip":
            out = gzip.decompress(data)
        elif kind == "bz2":
            out = bz2.decompress(data)
        else:                                              # lzma / xz
            if data[:3] == b"\x5d\x00\x00":
                out = lzma.decompress(data, format=lzma.FORMAT_ALONE)
            else:
                out = lzma.decompress(data)
    except (zlib.error, OSError, EOFError, lzma.LZMAError):
        return None
    return kind, out


def _try_decode_ascii(data: bytes) -> tuple[str, bytes] | None:
    """Decode a base64 / base85 text blob, validated by round-trip.

    Prefers a decoding whose output looks like a further layer; falls back to
    the first that round-trips exactly (a terminal base64 of plain data).
    """
    if not _is_ascii_ish(data):
        return None
    candidates: list[tuple[str, bytes]] = []
    for kind, decode, encode in (
        ("base85", base64.b85decode, base64.b85encode),
        ("base85", base64.a85decode, base64.a85encode),
        ("base64", lambda d: base64.b64decode(d, validate=True), base64.b64encode),
    ):
        try:
            out = decode(data)
            if not out or encode(out) != data:             # must round-trip exactly
                continue
        except (binascii.Error, ValueError):
            continue
        if _sniff_peelable(out):
            return kind, out                               # clearly a real layer
        candidates.append((kind, out))
    return candidates[0] if candidates else None


# ── recursive peeling ──────────────────────────────────────────────────────

def _summarize_consts(consts) -> list[str]:
    """repr-truncated summary of the non-code consts of a code object.

    Surfaces embedded keys/strings/ints (with byte lengths) without needing a
    matching interpreter; nested code objects are represented as tree children
    instead, so they are skipped here.
    """
    out: list[str] = []
    for c in consts:
        if isinstance(c, types.CodeType):
            continue
        r = repr(c)
        if len(r) > _CONST_REPR_CAP:
            r = r[:_CONST_REPR_CAP] + "..."
        if isinstance(c, (bytes, bytearray)):
            out.append(f"bytes[{len(c)}]: {r}")
        elif isinstance(c, str):
            out.append(f"str[{len(c)}]: {r}")
        else:
            out.append(f"{type(c).__name__}: {r}")
    return out


def _code_node(code: types.CodeType, depth: int, budget: _Budget) -> LayerNode:
    """Walk a code object into a 'marshal' node, recursing nested layers.

    Nested code objects in the consts become code children; const bytes/str
    that themselves look like a packed layer (compression / marshal, reached
    via an encoding) are peeled and attached too, so an embedded second-stage
    blob is surfaced. Plain data consts stay in the summary.
    """
    node = LayerNode(
        kind="marshal",
        name=code.co_name,
        co_names=tuple(code.co_names),
        co_varnames=tuple(code.co_varnames),
        co_filename=code.co_filename,
        co_flags=code.co_flags,
        argcount=code.co_argcount,
        co_consts_summary=_summarize_consts(code.co_consts),
        code_obj=code,
    )
    if depth >= budget.max_depth:
        return node
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            node.children.append(_code_node(const, depth + 1, budget))
        elif isinstance(const, (bytes, bytearray, str)):
            blob = const.encode("latin-1") if isinstance(const, str) else bytes(const)
            child = _peel_candidate(blob, depth + 1, budget)
            if child is not None:
                node.children.append(child)
    return node


def _peel(data: bytes, depth: int, budget: _Budget) -> LayerNode:
    """Peel one layer off `data` and recurse into what it exposes."""
    if depth >= budget.max_depth:
        return LayerNode(kind="raw", detail=f"{len(data)} bytes (max depth reached)")

    # 1. a marshalled code object
    if _looks_marshalled(data):
        try:
            obj = marshal.loads(data)
        except (ValueError, EOFError, TypeError):
            obj = None
        if isinstance(obj, types.CodeType):
            return _code_node(obj, depth, budget)

    # 2. a compression wrapper
    dec = _try_decompress(data)
    if dec is not None:
        kind, out = dec
        if not budget.spend(len(out)):
            return LayerNode(kind=kind, detail="output exceeds size budget",
                             children=[LayerNode(kind="raw",
                                                 detail=f"{len(out)} bytes (truncated)")])
        return LayerNode(kind=kind, detail=f"-> {len(out)} bytes",
                         children=[_peel(out, depth + 1, budget)])

    # 3. a base64 / base85 text wrapper
    dec = _try_decode_ascii(data)
    if dec is not None:
        kind, out = dec
        return LayerNode(kind=kind, detail=f"-> {len(out)} bytes",
                         children=[_peel(out, depth + 1, budget)])

    return LayerNode(kind="raw", detail=f"{len(data)} bytes")


def _is_interesting(node: LayerNode) -> bool:
    """True if the subtree contains a code object or a compression layer.

    Used to reject a lone base64/base85 decode of ordinary data — only a blob
    that actually unpacks into code or a compressed stage is worth surfacing.
    """
    return any(n.kind in ("marshal", "zlib", "gzip", "bz2", "lzma")
               for n in node.walk())


def _peel_candidate(data: bytes, depth: int, budget: _Budget) -> LayerNode | None:
    """Peel `data` but keep the result only if it reveals a real layer."""
    node = _peel(data, depth, budget)
    return node if _is_interesting(node) else None


# ── source loading ─────────────────────────────────────────────────────────

def _literal_blobs(src: str) -> list[tuple[str, bytes]]:
    """`ast.literal_eval` each top-level bytes/str assignment as a candidate.

    Static only: the module is parsed, never imported or executed. Returns
    (variable-name, blob-bytes) for each assignment whose value is a bytes or
    str literal.
    """
    out: list[tuple[str, bytes]] = []
    try:
        tree = ast.parse(src)
    except SyntaxError as exc:
        logger.warning("source did not parse: %s", exc)
        return out
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        try:
            value = ast.literal_eval(node.value)
        except (ValueError, SyntaxError, TypeError):
            continue
        if not isinstance(value, (bytes, str)):
            continue
        blob = value.encode("latin-1") if isinstance(value, str) else value
        names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        out.append((names[0] if names else "<literal>", blob))
    return out


def unwrap(source: bytes | str | Path, *, max_depth: int = 16) -> UnwrapResult:
    """Recursively peel a layered/marshalled Python blob into a layer tree.

    `source` may be raw bytes (a blob or a `.pyc`), a path to a file, or a
    string of Python source. For a `.py`/text source, each top-level bytes/str
    literal is lifted with `ast.literal_eval` and peeled; the module is never
    imported or executed. Returns an `UnwrapResult` whose `root` is the tree of
    detected layers and code objects. Read-only and in-memory.
    """
    budget = _Budget(max_depth=max_depth)
    label = str(source) if isinstance(source, (str, Path)) else "<bytes>"
    pyver: int | None = None

    # Resolve the input to either python-source text or a raw blob.
    text: str | None = None
    data: bytes | None = None
    if isinstance(source, (str, Path)):
        p = Path(source)
        is_file = False
        try:
            is_file = p.is_file()
        except OSError:
            is_file = False
        if is_file:
            raw = p.read_bytes()
            if p.suffix == ".pyc":
                pyver = detect_pyc_version(raw)
                data = raw[16:]                            # strip the pyc header
            else:
                try:
                    text = raw.decode("utf-8")
                except UnicodeDecodeError:
                    data = raw                             # a binary blob file
        elif isinstance(source, str):
            text = source                                  # inline Python source
            label = "<source>"
        else:
            return UnwrapResult(source=label, error=f"no such file: {p}")
    else:
        data = bytes(source)

    if text is not None:
        blobs = _literal_blobs(text)
        children: list[LayerNode] = []
        for name, blob in blobs:
            peeled = _peel(blob, 0, budget)
            if _is_interesting(peeled):
                children.append(LayerNode(kind="pyliteral", name=name,
                                          detail=f"{len(blob)} bytes literal",
                                          children=[peeled]))
        if not children:
            return UnwrapResult(source=label, truncated=budget.truncated,
                                error="no packed Python literal found in source")
        root = (children[0] if len(children) == 1
                else LayerNode(kind="pyliteral", detail=f"{len(children)} literals",
                               children=children))
    else:
        assert data is not None
        root = _peel(data, 0, budget)

    if pyver is None:
        for node in root.walk():
            if node.co_filename is not None:               # first code node
                pyver = detect_pyc_version(data) if data else None
                break
    return UnwrapResult(source=label, root=root, python_version=pyver,
                        truncated=budget.truncated)


# ── cross-version disassembly ──────────────────────────────────────────────

def disassemble(code_or_bytes, *, version: str = "auto") -> str:
    """Disassemble a code object or marshalled/pyc bytes, cross-version aware.

    Detects the compile version from a pyc magic when present (else the host).
    Prefers `xdis` when importable — it carries the opcode tables for a target
    that differs from the host; otherwise falls back to stdlib `dis` with a
    one-line WARNING, since `dis` decodes with the host's table and can be
    wrong when host != target. The `co_names` / `co_consts` tree from `unwrap`
    is always valid regardless.
    """
    detected = None
    body = None
    code = None
    if isinstance(code_or_bytes, types.CodeType):
        code = code_or_bytes
    else:
        body = bytes(code_or_bytes)
        detected = detect_pyc_version(body)
        if detected is not None:
            body = body[16:]                               # a headered pyc
        try:
            loaded = marshal.loads(body)
            if isinstance(loaded, types.CodeType):
                code = loaded
        except (ValueError, EOFError, TypeError):
            code = None

    if version != "auto":
        try:
            detected = int(str(version).replace(".", ""))
        except ValueError:
            pass

    # Prefer xdis (handles host != target opcode tables). Guarded: its absence
    # must never break the primary unwrap path, only this optional disasm.
    try:
        import io

        import xdis                                        # noqa: F401
        from xdis.version_info import version_tuple_to_str

        if code is None:
            return "WARNING: could not load a code object to disassemble."
        buf = io.StringIO()
        if detected is not None:
            vt = ((detected // 100, (detected // 10) % 10, detected % 10)
                  if detected >= 100 else (detected // 10, detected % 10))
            from xdis.disasm import disco
            disco(vt, code, 0, out=buf)
            header = f"# xdis disassembly (target Python {version_tuple_to_str(vt)})\n"
        else:
            from xdis.std import dis as xdis_dis
            xdis_dis(code, file=buf)
            header = "# xdis disassembly (host Python opcode table)\n"
        return header + buf.getvalue()
    except ImportError:
        pass
    except Exception as exc:                               # xdis choked — fall back
        logger.warning("xdis disassembly failed (%s); using stdlib dis", exc)

    # stdlib fallback
    import dis
    import io
    warn = ("WARNING: disassembled with the host interpreter's opcode table; "
            "if the target was compiled for a different Python version the "
            "opcodes may be wrong. The co_names/co_consts tree is always "
            "valid.\n")
    if code is None:
        return warn + "(could not load a code object to disassemble)"
    buf = io.StringIO()
    try:
        dis.dis(code, file=buf)
    except Exception as exc:
        return warn + f"(stdlib dis failed: {exc})"
    return warn + buf.getvalue()
