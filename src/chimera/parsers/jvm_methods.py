"""Parse method records out of jadx-decompiled Java/Kotlin sources.

Regex-based; tolerates jadx output but not arbitrary handwritten code.
False positives in `is_native` are biased low: the `native` modifier
must appear as a whole word in the modifier list.

Limitation: jadx output uses unqualified type names in source bodies
(e.g. `String` rather than `java.lang.String`). The parser preserves
this — `LString;` rather than `Ljava/lang/String;`. This is consistent
across both the JVM and (parser-driven) JNI sides of the static
linker, so non-overloaded bindings still match. Overloaded bindings
that rely on canonical descriptor matching against runtime-recovered
signatures (e.g. RegisterNatives entries) may need import-resolved
descriptors; that resolution is deferred to a follow-up.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator


_JAVA_METHOD_RX = re.compile(
    r"""
    ^[\ \t]*
    (?:@\w[\w.]*(?:\([^)]*\))?\s+)*           # annotations
    (?P<mods>(?:(?:public|private|protected|static|final|abstract|
                  native|synchronized|strictfp|default)\s+)+)
    (?P<ret>[\w.\[\]<>,\s\?]+?)\s+            # return type
    (?P<name>\w+)\s*
    \((?P<params>[^)]*)\)\s*
    (?:throws\s+[\w.,\s]+)?\s*
    [{;]
    """,
    re.VERBOSE | re.MULTILINE,
)

_KOTLIN_FUN_RX = re.compile(
    r"""
    ^[\ \t]*
    (?:@\w[\w.]*(?:\([^)]*\))?\s+)*
    (?P<mods>(?:(?:public|private|protected|internal|external|inline|
                  suspend|operator|infix|tailrec|abstract|final|open|
                  override)\s+)*)
    fun\s+
    (?:<[^>]+>\s+)?
    (?:\w+\.)?
    (?P<name>\w+)\s*
    \((?P<params>[^)]*)\)
    """,
    re.VERBOSE | re.MULTILINE,
)


_JAVA_PRIMS = {
    "boolean": "Z", "byte": "B", "char": "C", "double": "D",
    "float": "F", "int": "I", "long": "J", "short": "S", "void": "V",
}


@dataclass
class JvmMethod:
    class_fqcn: str
    name: str
    smali_sig: str
    is_native: bool
    file: str
    line: int
    language: str
    modifiers: tuple[str, ...] = field(default_factory=tuple)


def _java_type_to_smali(t: str) -> str:
    t = t.strip()
    arr = 0
    while t.endswith("[]"):
        arr += 1
        t = t[:-2].rstrip()
    if t.endswith("..."):
        arr += 1
        t = t[:-3].rstrip()
    if t in _JAVA_PRIMS:
        s = _JAVA_PRIMS[t]
    else:
        t = re.sub(r"<[^>]*>", "", t).strip()
        s = "L" + t.replace(".", "/") + ";"
    return "[" * arr + s


def _split_params(params_src: str) -> list[str]:
    params_src = params_src.strip()
    if not params_src:
        return []
    out: list[str] = []
    depth = 0
    cur: list[str] = []
    for ch in params_src + ",":
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth -= 1
        if ch == "," and depth == 0:
            tok = "".join(cur).strip()
            if tok:
                # strip annotations
                tok = re.sub(r"@\w[\w.]*(?:\([^)]*\))?\s+", "", tok).strip()
                # last whitespace token is the param name; the rest is the type
                parts = tok.rsplit(None, 1)
                type_part = parts[0] if len(parts) >= 2 else tok
                out.append(_java_type_to_smali(type_part))
            cur = []
            continue
        cur.append(ch)
    return out


def _build_smali_sig(params_src: str, ret_src: str) -> str:
    return "(" + "".join(_split_params(params_src)) + ")" + _java_type_to_smali(ret_src)


def parse_java_file(path: Path, package: str) -> list[JvmMethod]:
    text = path.read_text(encoding="utf-8", errors="replace")
    fqcn = f"{package}.{path.stem}" if package else path.stem
    methods: list[JvmMethod] = []
    for m in _JAVA_METHOD_RX.finditer(text):
        line = text.count("\n", 0, m.start()) + 1
        mods = re.findall(r"\w+", m.group("mods") or "")
        try:
            smali = _build_smali_sig(m.group("params") or "", m.group("ret") or "void")
        except (ValueError, AttributeError, TypeError):
            smali = "(?)?"
        methods.append(JvmMethod(
            class_fqcn=fqcn, name=m.group("name"),
            smali_sig=smali, is_native="native" in mods,
            file=str(path), line=line, language="java",
            modifiers=tuple(mods),
        ))
    return methods


def parse_kotlin_file(path: Path, package: str) -> list[JvmMethod]:
    text = path.read_text(encoding="utf-8", errors="replace")
    fqcn = f"{package}.{path.stem}" if package else path.stem
    methods: list[JvmMethod] = []
    for m in _KOTLIN_FUN_RX.finditer(text):
        line = text.count("\n", 0, m.start()) + 1
        mods = re.findall(r"\w+", m.group("mods") or "")
        methods.append(JvmMethod(
            class_fqcn=fqcn, name=m.group("name"),
            smali_sig="(?)?",  # filled by caller when type info available
            is_native="external" in mods,
            file=str(path), line=line, language="kotlin",
            modifiers=tuple(mods),
        ))
    return methods


def iter_jvm_files(sources_dir: Path) -> Iterator[tuple[Path, str]]:
    for p in Path(sources_dir).rglob("*"):
        if p.is_file() and p.suffix in (".java", ".kt"):
            rel = p.relative_to(sources_dir)
            package = ".".join(rel.parent.parts)
            yield p, package


def parse_jvm_methods(sources_dir: Path, *, max_methods: int = 50000) -> list[JvmMethod]:
    out: list[JvmMethod] = []
    for path, pkg in iter_jvm_files(Path(sources_dir)):
        if len(out) >= max_methods:
            break
        try:
            if path.suffix == ".java":
                out.extend(parse_java_file(path, pkg))
            else:
                out.extend(parse_kotlin_file(path, pkg))
        except OSError:
            continue
    if len(out) > max_methods:
        out = out[:max_methods]
    return out


@dataclass
class Callsite:
    caller: JvmMethod
    callee_name: str
    line: int


def _index_method_starts(text: str, methods: list[JvmMethod]) -> list[tuple[int, JvmMethod]]:
    """Return [(start_offset_in_text, method), ...] sorted by offset.

    Used to attribute a callsite line to the closest preceding method
    declaration in the same file.
    """
    out: list[tuple[int, JvmMethod]] = []
    pos = 0
    for m in methods:
        idx = text.find(f" {m.name}(", pos)
        if idx == -1:
            idx = text.find(f"\t{m.name}(", pos)
        if idx == -1:
            idx = text.find(f"{m.name}(", pos)
        if idx == -1:
            continue
        out.append((idx, m))
        pos = idx + 1
    out.sort()
    return out


def find_callsites(
    methods: list[JvmMethod],
    native_method_names: set[str],
) -> list[Callsite]:
    """Find calls to any name in `native_method_names` and attribute
    each to its enclosing method (the closest method whose start offset
    precedes the call).

    File-grouping: methods from the same file share one re-read. This
    is O(files × native_names); native_names is small in practice.
    """
    if not native_method_names:
        return []
    by_file: dict[str, list[JvmMethod]] = {}
    for m in methods:
        by_file.setdefault(m.file, []).append(m)
    out: list[Callsite] = []
    for file, ms in by_file.items():
        try:
            text = Path(file).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        starts = _index_method_starts(text, ms)
        for callee in native_method_names:
            for hit in re.finditer(rf"\b{re.escape(callee)}\s*\(", text):
                line = text.count("\n", 0, hit.start()) + 1
                # find enclosing method: largest start <= hit.start()
                enclosing: JvmMethod | None = None
                for off, mm in starts:
                    if off > hit.start():
                        break
                    enclosing = mm
                if enclosing is None or enclosing.name == callee:
                    continue
                out.append(Callsite(caller=enclosing, callee_name=callee, line=line))
    return out
