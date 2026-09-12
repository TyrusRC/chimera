"""Deobfuscate standalone JavaScript / HTML — the web counterpart to pyunwrap.

chimera's only JS path was the React Native pipeline (webcrack on a bundle);
an obfuscated `.html`/`.js` (a web CTF challenge, or a malicious dropper's
inline script) had no entry point, and `analyze` mis-sniffs HTML as a binary.

This runs the two transforms that actually make such code readable:
  1. **webcrack** — undo control-flow flattening, inline the string array,
     unminify, and split bundled modules (the AST deobfuscator the RN pipeline
     already depends on).
  2. **prettier** (or a built-in line-splitter fallback) — webcrack leaves
     megabyte-scale object literals on one line; splitting them is what makes
     the output greppable/readable instead of one unreadable blob.

Inline `<script>` bodies are extracted from HTML first (stdlib parser, no dep).
A real web app, though, keeps its code in EXTERNAL files: `<script src=…>` plus
ES `import`/`export … from`/dynamic `import()`. `collect_local_scripts` walks
that module graph from an HTML/JS entry point (local files only — remote URLs
and bare npm packages are skipped; network stays off) so a multi-file page can
be deobfuscated from its `index.html` in one call. `resolve_const_index` then
reads an element out of a constant array literal statically (no code execution)
— the recurring web-CTF "indexed table → flag" pattern (a hardcoded index into
a word/table constant).

node + webcrack/prettier are external (reachable on PATH or via `npx --yes`);
without them this returns a clear "not available" result rather than raising.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path

# External <script src="..."> references in HTML.
_SRC_RE = re.compile(r"""<script\b[^>]*?\bsrc\s*=\s*["']([^"']+)["']""", re.I)
# ES module specifiers: `… from "x"`, bare `import "x"`, dynamic `import("x")`.
_IMPORT_RE = re.compile(
    r"""(?:\bimport\b|\bexport\b)[^;]*?\bfrom\s*["']([^"']+)["']"""
    r"""|\bimport\s*\(\s*["']([^"']+)["']\s*\)"""
    r"""|\bimport\s+["']([^"']+)["']""",
    re.I)


class _ScriptExtractor(HTMLParser):
    """Collect the text of inline <script> elements (those without a src)."""

    def __init__(self) -> None:
        super().__init__()
        self.scripts: list[str] = []
        self._in_script = False
        self._buf: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "script" and not dict(attrs).get("src"):
            self._in_script = True
            self._buf = []

    def handle_endtag(self, tag):
        if tag == "script" and self._in_script:
            self._in_script = False
            body = "".join(self._buf).strip()
            if body:
                self.scripts.append(body)

    def handle_data(self, data):
        if self._in_script:
            self._buf.append(data)


def extract_scripts(text: str, *, is_html: bool) -> list[str]:
    """Return the JS bodies to deobfuscate — inline scripts for HTML, else all."""
    if not is_html:
        return [text]
    p = _ScriptExtractor()
    p.feed(text)
    return p.scripts


def _is_local_spec(spec: str) -> bool:
    """A module specifier we can resolve to a file — not remote, not a bare pkg."""
    if not spec:
        return False
    if re.match(r"[a-z][a-z0-9+.-]*://", spec, re.I) or spec.startswith("//"):
        return False  # http(s):// or protocol-relative — remote, don't fetch
    return spec.startswith((".", "/")) or spec.lower().endswith((".js", ".mjs", ".cjs"))


def _resolve_spec(spec: str, base_dir: Path) -> Path | None:
    """Resolve a local module specifier under base_dir to an existing file.

    A leading `/` is treated as the served site root (the entry's directory),
    not the filesystem root — that is what a challenge folder means by it.
    """
    spec = spec.split("?", 1)[0].split("#", 1)[0].lstrip("/")
    cand = base_dir / spec
    tries = [cand]
    if cand.suffix == "":  # extensionless import → try the usual endings
        tries += [cand.with_suffix(".js"), cand.with_suffix(".mjs"), cand / "index.js"]
    for t in tries:
        try:
            if t.is_file():
                return t.resolve()
        except OSError:
            pass
    return None


def collect_local_scripts(entry: Path, *, max_files: int = 200) -> tuple[list[Path], list[str]]:
    """BFS the web module graph from an HTML/JS entry point.

    Returns (ordered existing local .js files, skipped/unresolvable specifiers).
    HTML roots come from `<script src>`; a JS entry is its own root. Both then
    follow local ES `import`/`export … from` and dynamic `import()` edges.
    """
    entry = entry.resolve()
    text = entry.read_text(errors="replace")
    is_html = entry.suffix.lower() in (".html", ".htm") or "<script" in text[:4096].lower()
    seen: set[Path] = set()
    ordered: list[Path] = []
    skipped: list[str] = []
    queue: list[Path] = []

    if is_html:
        for spec in _SRC_RE.findall(text):
            if not _is_local_spec(spec):
                skipped.append(spec)
                continue
            r = _resolve_spec(spec, entry.parent)
            queue.append(r) if r else skipped.append(spec)
    else:
        queue.append(entry)

    while queue and len(ordered) < max_files:
        f = queue.pop(0)
        if f in seen:
            continue
        seen.add(f)
        ordered.append(f)
        try:
            ftext = f.read_text(errors="replace")
        except OSError:
            continue
        for groups in _IMPORT_RE.findall(ftext):
            spec = next((g for g in groups if g), "")
            if not spec:
                continue
            if not _is_local_spec(spec):
                skipped.append(spec)
                continue
            r = _resolve_spec(spec, f.parent)
            if r and r not in seen:
                queue.append(r)
            elif not r:
                skipped.append(spec)
    return ordered, sorted(set(skipped))


def _split_array_literal(js: str, open_pos: int) -> list[str] | None:
    """Split a `[ … ]` literal at `open_pos` into its top-level element tokens.

    Respects string quotes/escapes and nested (){}[] so commas inside them do
    not split. Returns None if the bracket is unterminated.
    NOTE: a sparse element (`,,`) is kept as an empty token, so an array with
    real holes would misalign an index — these tables never have holes.
    """
    i, n = open_pos + 1, len(js)
    depth = 0
    quote = ""
    esc = False
    cur: list[str] = []
    out: list[str] = []
    while i < n:
        ch = js[i]
        if quote:
            cur.append(ch)
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == quote:
                quote = ""
        elif ch in "\"'`":
            quote = ch
            cur.append(ch)
        elif ch in "([{":
            depth += 1
            cur.append(ch)
        elif ch in ")}":
            depth -= 1
            cur.append(ch)
        elif ch == "]":
            if depth == 0:
                seg = "".join(cur).strip()
                if seg or out:  # keep a trailing element, drop a trailing comma
                    out.append(seg)
                return out
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
        i += 1
    return None


def _unescape_js_string(s: str) -> str:
    simple = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "0": "\0"}

    def repl(m: re.Match) -> str:
        e = m.group(0)
        if e[1] in "uxX":
            return chr(int(e[2:], 16))
        return simple.get(e[1], e[1])

    return re.sub(r"\\(u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|.)", repl, s)


def _as_scalar(tok: str) -> str | None:
    """A string/number literal token → its Python value; None if not a scalar."""
    tok = tok.strip()
    if len(tok) >= 2 and tok[0] in "\"'`" and tok[-1] == tok[0]:
        return _unescape_js_string(tok[1:-1])
    if re.fullmatch(r"-?\d+(?:\.\d+)?", tok):
        return tok
    return None


def resolve_const_index(js: str, name: str, index: int) -> str | None:
    """Element `index` of a `const/let/var NAME = [ … ]` literal, statically.

    No code execution: it finds the declaration, splits the array literal, and
    returns the element if it is a simple string/number. None if the name isn't
    a const array, the index is out of range, or the element isn't a scalar.
    """
    m = re.search(rf"(?:export\s+)?(?:const|let|var)\s+{re.escape(name)}\s*=\s*\[", js)
    if not m:
        return None
    elems = _split_array_literal(js, m.end() - 1)
    if elems is None or not (0 <= index < len(elems)):
        return None
    return _as_scalar(elems[index])


def _safe_label(f: Path, base: Path) -> str:
    try:
        rel = f.relative_to(base)
    except ValueError:
        rel = Path(f.name)
    return re.sub(r"[^A-Za-z0-9_.-]", "_", str(rel))


def node_tool_cmd(tool: str) -> list[str] | None:
    """Resolve a node CLI: a PATH binary, else `npx --yes <tool>` if npx exists."""
    if shutil.which(tool):
        return [tool]
    if shutil.which("npx"):
        return ["npx", "--yes", tool]
    return None


def _fallback_split(js: str, max_col: int = 200) -> str:
    """Dependency-free line-splitter for when prettier is absent.

    Not a formatter — it just inserts newlines after ``;`` ``{`` ``}`` on lines
    longer than `max_col` (skipping string/regex bodies is out of scope), so a
    single multi-MB statement becomes something grep/less can page. Good enough
    to read structure; prettier is preferred when available.
    """
    out: list[str] = []
    for line in js.splitlines():
        if len(line) <= max_col:
            out.append(line)
            continue
        cur = []
        depth = 0
        for ch in line:
            cur.append(ch)
            if ch in "\"'`":
                pass  # naive: we don't track strings; acceptable for readability
            if ch in ";{}":
                out.append("".join(cur))
                cur = []
        if cur:
            out.append("".join(cur))
    return "\n".join(out)


def deobfuscate(path: str, *, out_dir: str | None = None, prettier: bool = True,
                resolve: str | None = None, timeout: int = 300) -> dict:
    """Deobfuscate the JS/HTML at `path`; write cleaned scripts under out_dir.

    Follows the web module graph: inline `<script>` bodies plus every local
    external `<script src>` / ES-imported file reachable from the entry. Returns
    availability, the module graph, and per-output-file paths + byte sizes
    (never the multi-MB content itself — read the files as needed).

    `resolve="NAME[IDX]"` short-circuits to STATIC constant resolution — it reads
    element IDX of the `const NAME = [ … ]` array literal across the collected
    sources without running node or webcrack (the "indexed table → flag" case).
    """
    src = Path(path)
    if not src.exists():
        return {"available": True, "error": f"file not found: {path}"}

    text = src.read_text(errors="replace")
    is_html = src.suffix.lower() in (".html", ".htm") or "<script" in text[:4096].lower()
    files, skipped = collect_local_scripts(src)
    sources: list[tuple[str, str]] = []
    if is_html:
        for i, body in enumerate(extract_scripts(text, is_html=True)):
            sources.append((f"inline_{i}", body))
    for f in files:
        try:
            sources.append((_safe_label(f, src.resolve().parent), f.read_text(errors="replace")))
        except OSError:
            pass
    module_graph = [str(f) for f in files]

    if resolve is not None:  # static, no node needed — answer and return
        rm = re.fullmatch(r"\s*([A-Za-z_$][\w$]*)\s*\[\s*(\d+)\s*\]\s*", resolve)
        if not rm:
            return {"available": True, "is_html": is_html, "module_graph": module_graph,
                    "resolved": {"expr": resolve, "error": "expected NAME[INDEX]"}}
        joined = "\n".join(t for _, t in sources)
        val = resolve_const_index(joined, rm.group(1), int(rm.group(2)))
        return {"available": True, "is_html": is_html, "sources": len(sources),
                "module_graph": module_graph, "skipped_refs": skipped,
                "resolved": {"expr": resolve, "value": val},
                "note": "static const resolution (no deobfuscation run)"}

    if not sources:
        return {"available": True, "is_html": is_html, "skipped_refs": skipped,
                "error": "no scripts found (no inline <script>, no resolvable "
                         "external/imported .js)"}

    wc = node_tool_cmd("webcrack")
    if wc is None:
        return {"available": False,
                "error": "webcrack not found — `npm i -g webcrack` (needs node)."}

    out = Path(out_dir) if out_dir else src.parent / f"{src.stem}_deobf"
    out.mkdir(parents=True, exist_ok=True)

    pretty = node_tool_cmd("prettier") if prettier else None
    output_files: list[dict] = []
    errors: list[str] = []
    for i, (label, body) in enumerate(sources):
        raw = out / f"{i:02d}_{label}"
        if raw.suffix.lower() not in (".js", ".mjs", ".cjs"):
            raw = raw.with_suffix(raw.suffix + ".js")
        raw.write_text(body)
        wc_out = out / f"{i:02d}_webcrack"
        try:
            proc = subprocess.run(wc + ["-o", str(wc_out), str(raw)],
                                  capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            errors.append(f"script {i}: webcrack timed out")
            continue
        if proc.returncode != 0:
            errors.append(f"script {i}: webcrack rc={proc.returncode}: "
                          f"{proc.stderr[-400:]}")
            continue
        for js in sorted(wc_out.rglob("*.js")):
            if pretty:
                try:
                    subprocess.run(pretty + ["--write", str(js)],
                                   capture_output=True, text=True, timeout=timeout)
                except subprocess.TimeoutExpired:
                    pass
            else:
                js.write_text(_fallback_split(js.read_text(errors="replace")))
            output_files.append({"path": str(js), "size": js.stat().st_size})

    return {
        "available": True, "is_html": is_html, "scripts_found": len(sources),
        "module_graph": module_graph, "skipped_refs": skipped,
        "output_dir": str(out), "output_files": output_files,
        "formatter": ("prettier" if pretty else "builtin-splitter"),
        "webcrack": " ".join(wc),
        "errors": errors,
        "note": (f"{len(output_files)} cleaned file(s) from {len(sources)} source(s) — "
                 "grep/read them; content not inlined to keep it out of context"),
    }
