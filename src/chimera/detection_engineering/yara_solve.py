"""Solve a YARA rule: synthesise a file that MATCHES its condition.

The inverse of `yara_author`. `yara_scan` tells you whether a file matches a
rule; this answers "what input WOULD match?" — the YARA-keygen CTF challenge
(reverse a rule to the flag it accepts) and, defensively, a rule-QA check
("does any input actually satisfy this, and what does one look like?").

Approach: the condition is a conjunction of constraints over the file bytes.
Byte/int reads (`uint8/uint16/uint32/int8/int16/int32` and their `be` variants),
`filesize`, C-arithmetic and comparisons translate directly to a Z3 bit-vector
model over the file. Hash windows (`hash.md5/sha1/sha256/crc32(offset, len)`)
can't be expressed to an SMT solver, so short windows are brute-forced to pin
their exact bytes; a full-file hash is left as a post-hoc verifier.

Scope (v1): a single rule whose condition is a flat `and` of the atoms above.
`or`, `not`, `for … of`, and string-identifier (`$a at N`) atoms are reported
as unsupported rather than silently dropped. Z3 is an optional extra
(`chimera[solve]`); without it this returns a clear "not available" result.
"""
from __future__ import annotations

import binascii
import hashlib
import itertools
import re
from pathlib import Path


def z3_available() -> bool:
    try:
        import z3  # noqa: F401
        return True
    except Exception:
        return False


# ── condition tokenizer + precedence-climbing parser ───────────────────────
# YARA binds bitwise operators TIGHTER than comparisons (unlike C), so
# `uint8(3) & 128 == 0` means `(uint8(3) & 128) == 0`.
_TOK = re.compile(
    r"\s*(uint8|uint16|uint32|int8|int16|int32|"
    r"uint16be|uint32be|int16be|int32be|filesize|"
    r"0x[0-9a-fA-F]+|\d+|<<|>>|<=|>=|==|!=|[()%^&|<>+\-*/,~])")
_BP = {"*": 7, "/": 7, "%": 7, "+": 6, "-": 6, "<<": 5, ">>": 5,
       "&": 4, "^": 3, "|": 2, "<": 1, "<=": 1, ">": 1, ">=": 1,
       "==": 0, "!=": 0}
_READS = {"uint8", "uint16", "uint32", "int8", "int16", "int32",
          "uint16be", "uint32be", "int16be", "int32be"}
_HASH_RE = re.compile(
    r"hash\.(md5|sha1|sha256|crc32)\((\d+),\s*(\w+)\)\s*==\s*"
    r"(0x[0-9a-fA-F]+|\"[0-9a-fA-F]+\")")


def _lex(text: str) -> list[str]:
    toks, i = [], 0
    while i < len(text):
        m = _TOK.match(text, i)
        if not m:
            raise ValueError(f"cannot tokenise near {text[i:i+24]!r}")
        toks.append(m.group(1))
        i = m.end()
    return toks


def solve_yara(source: str, *, size: int | None = None,
               max_hash_len: int = 3, printable: bool = True,
               timeout_s: int = 60) -> dict:
    """Find a file that matches the YARA rule in `source`.

    `size` overrides / supplies the file length when the rule has no
    `filesize == N`. `max_hash_len` bounds the brute-force window for hash
    atoms. `printable` restricts bytes to 0x20–0x7e (a flag is ASCII); set
    False for a binary target. Returns availability, the solved bytes, whether
    yara-python confirms the match, and any unsupported/unsolved atoms.
    """
    if not z3_available():
        return {"available": False,
                "error": 'z3 not installed — pip install "chimera[solve]"'}
    import z3

    cond_m = re.search(r"condition:\s*(.*?)\s*}\s*$", source, re.S)
    if not cond_m:
        return {"available": True, "error": "no condition block found"}
    cond = cond_m.group(1).strip()

    if size is None:
        fs = re.search(r"filesize\s*==\s*(\d+)", cond)
        if not fs:
            return {"available": True,
                    "error": "no `filesize == N` in rule; pass size=..."}
        size = int(fs.group(1))
    N = size
    b = [z3.BitVec(f"b{i}", 8) for i in range(N)]
    s = z3.Solver()
    s.set("timeout", timeout_s * 1000)
    if printable:
        for x in b:
            s.add(z3.ULE(0x20, x), z3.ULE(x, 0x7e))

    def read(kind: str, off: int):
        be = kind.endswith("be")
        base = kind[:-2] if be else kind
        signed = base.startswith("int")
        width = {"uint8": 1, "int8": 1, "uint16": 2, "int16": 2,
                 "uint32": 4, "int32": 4}[base]
        parts = [b[off + i] for i in range(width)]
        if off + width > N:
            raise IndexError(f"{kind}({off}) reads past filesize {N}")
        chunk = parts if be else list(reversed(parts))  # LE default
        val = chunk[0] if len(chunk) == 1 else z3.Concat(*chunk)
        ext = 64 - width * 8
        return (z3.SignExt(ext, val) if signed else z3.ZeroExt(ext, val)) if ext else val

    def parse(toks: list[str]):
        pos = 0

        def peek():
            return toks[pos] if pos < len(toks) else None

        def nxt():
            nonlocal pos
            t = toks[pos]
            pos += 1
            return t

        def atom():
            t = nxt()
            if t in _READS:
                assert nxt() == "("
                off = int(nxt(), 0)
                assert nxt() == ")"
                return read(t, off)
            if t == "filesize":
                return z3.BitVecVal(N, 64)
            if t == "(":
                e = expr(0)
                assert nxt() == ")"
                return e
            if t == "~":
                return ~atom()
            return z3.BitVecVal(int(t, 0), 64)

        def apply(op, l, r):
            return {
                "+": lambda: l + r, "-": lambda: l - r, "*": lambda: l * r,
                "/": lambda: z3.UDiv(l, r), "%": lambda: z3.URem(l, r),
                "^": lambda: l ^ r, "&": lambda: l & r, "|": lambda: l | r,
                "<<": lambda: l << r, ">>": lambda: z3.LShR(l, r),
                "<": lambda: z3.ULT(l, r), "<=": lambda: z3.ULE(l, r),
                ">": lambda: z3.UGT(l, r), ">=": lambda: z3.UGE(l, r),
                "==": lambda: l == r, "!=": lambda: l != r,
            }[op]()

        def expr(minbp):
            left = atom()
            while True:
                op = peek()
                if op is None or op not in _BP or _BP[op] < minbp:
                    break
                nxt()
                left = apply(op, left, expr(_BP[op] + 1))
            return left

        return expr(0)

    atoms = re.split(r"\s+and\s+", cond)
    unsupported, unsolved = [], []
    pinned = 0
    for a in atoms:
        a = a.strip().strip("()").strip()
        if not a:
            continue
        if a.startswith("hash."):
            hm = _HASH_RE.match(a)
            if not hm:
                unsupported.append(a)
                continue
            kind, off, length, want = hm.group(1), int(hm.group(2)), hm.group(3), hm.group(4)
            if length == "filesize" or int(length) > max_hash_len:
                continue  # not brute-forceable: leave as a final verifier
            length = int(length)
            want_v = (int(want, 0) if want.startswith("0x")
                      else want.strip('"').lower())
            rng = range(0x20, 0x7f) if printable else range(256)
            found = None
            for combo in itertools.product(rng, repeat=length):
                d = bytes(combo)
                dv = (binascii.crc32(d) & 0xffffffff if kind == "crc32"
                      else getattr(hashlib, kind)(d).hexdigest())
                if dv == want_v:
                    found = d
                    break
            if found:
                for i, c in enumerate(found):
                    s.add(b[off + i] == c)
                pinned += 1
            else:
                unsolved.append(a)
            continue
        # boolean sub-expression → a Z3 constraint
        if re.search(r"\bfor\b|\bof\b|\bnot\b|\bthem\b|\$", a) or " or " in f" {a} ":
            unsupported.append(a)
            continue
        try:
            s.add(parse(_lex(a)))
        except Exception as exc:  # keep going; report the atom
            unsupported.append(f"{a}  ({exc})")

    if s.check() != z3.sat:
        return {"available": True, "matched": False, "sat": False,
                "filesize": N, "pinned_hash_windows": pinned,
                "unsupported_atoms": unsupported, "unsolved_atoms": unsolved,
                "note": "UNSAT (or timeout) — unsupported atoms may over/under-constrain"}
    m = s.model()
    data = bytes((m[b[i]].as_long() if m[b[i]] is not None else 0) for i in range(N))

    matched = None
    try:
        import yara
        matched = bool(yara.compile(source=source).match(data=data))
    except Exception:
        matched = None  # yara-python absent or rule uses modules it can't load

    ascii_txt = data.decode("latin-1")
    return {
        "available": True, "sat": True, "matched": matched, "filesize": N,
        "data_hex": data.hex(), "ascii": ascii_txt,
        "printable": all(0x20 <= c < 0x7f for c in data),
        "pinned_hash_windows": pinned,
        "unsupported_atoms": unsupported, "unsolved_atoms": unsolved,
        "note": ("verified by yara-python" if matched
                 else "solved; yara-python could not confirm" if matched is None
                 else "solved but yara-python did NOT match — check unsupported atoms"),
    }


def solve_yara_file(path: str, **kw) -> dict:
    return solve_yara(Path(path).read_text(errors="replace"), **kw)
