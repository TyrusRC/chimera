"""JNI symbol mangling per JNI Specification §6.1.

The escape rules are:
    `.` and `/`  ->  `_`
    `_`          ->  `_1`
    `;`          ->  `_2`
    `[`          ->  `_3`
    Unicode > 0x7F -> `_XXXX` (4-digit lower-hex)

Overloaded methods append `__` followed by the mangled parameter
descriptor (i.e. the inside of the smali signature `(...)`, with the
return type omitted).
"""
from __future__ import annotations

import re


def _escape_identifier(s: str) -> str:
    out: list[str] = []
    for ch in s:
        c = ord(ch)
        if ch == "_":
            out.append("_1")
        elif ch == ";":
            out.append("_2")
        elif ch == "[":
            out.append("_3")
        elif ch in (".", "/"):
            out.append("_")
        elif c <= 0x7F and (ch.isalnum() or ch in "$"):
            out.append(ch)
        else:
            out.append(f"_{c:04x}")
    return "".join(out)


def mangle(class_fqcn: str, method: str, *, smali_sig: str | None = None,
           overloaded: bool = False) -> str:
    """Return the JNI symbol name for a Java method.

    `class_fqcn` may use either `.` or `/`. `smali_sig` is required when
    `overloaded=True` and must look like `(II)V`.
    """
    cls = _escape_identifier(class_fqcn)
    meth = _escape_identifier(method)
    base = f"Java_{cls}_{meth}"
    if not overloaded:
        return base
    if not smali_sig or not smali_sig.startswith("("):
        return base
    inside = smali_sig[1:smali_sig.index(")")] if ")" in smali_sig else smali_sig[1:]
    return f"{base}__{_escape_identifier(inside)}"


_UNMANGLE_TOKEN_RX = re.compile(r"_([0-9a-fA-F]{4})|_([1-3])|_")


def _unescape(s: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(s):
        m = _UNMANGLE_TOKEN_RX.match(s, i)
        if m and m.start() == i:
            if m.group(1) is not None:
                out.append(chr(int(m.group(1), 16)))
            elif m.group(2) is not None:
                out.append({"1": "_", "2": ";", "3": "["}[m.group(2)])
            else:
                out.append("/")
            i = m.end()
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def unmangle(symbol: str) -> tuple[str, str, str | None]:
    """Recover (class_internal, method, sig) from a `Java_*` symbol.

    `class_internal` uses `/` separators (JVM internal form). `sig` is
    `None` when the symbol is not the overloaded form; otherwise it is
    the parameter descriptor wrapped in parens. Return type cannot be
    recovered from the symbol alone — caller resolves it via the JVM
    side.
    """
    if not symbol.startswith("Java_"):
        raise ValueError(f"not a JNI symbol: {symbol}")
    body = symbol[len("Java_"):]
    if "__" in body:
        head, _, tail = body.partition("__")
        cls_meth = _unescape(head)
        sig = "(" + _unescape(tail) + ")"
    else:
        cls_meth = _unescape(body)
        sig = None
    if "/" in cls_meth:
        cls, _, meth = cls_meth.rpartition("/")
    else:
        cls, meth = "", cls_meth
    return cls, meth, sig
