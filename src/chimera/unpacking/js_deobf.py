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
node + webcrack/prettier are external (reachable on PATH or via `npx --yes`);
without them this returns a clear "not available" result rather than raising.
"""
from __future__ import annotations

import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path


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
                timeout: int = 300) -> dict:
    """Deobfuscate the JS/HTML at `path`; write cleaned scripts under out_dir.

    Returns availability, the inline scripts found, and per-output-file paths +
    byte sizes (never the multi-MB content itself — read the files as needed).
    """
    src = Path(path)
    if not src.exists():
        return {"available": True, "error": f"file not found: {path}"}
    wc = node_tool_cmd("webcrack")
    if wc is None:
        return {"available": False,
                "error": "webcrack not found — `npm i -g webcrack` (needs node)."}

    out = Path(out_dir) if out_dir else src.parent / f"{src.stem}_deobf"
    out.mkdir(parents=True, exist_ok=True)

    text = src.read_text(errors="replace")
    is_html = src.suffix.lower() in (".html", ".htm") or "<script" in text[:4096].lower()
    scripts = extract_scripts(text, is_html=is_html)
    if not scripts:
        return {"available": True, "error": "no inline <script> found in HTML",
                "is_html": is_html}

    pretty = node_tool_cmd("prettier") if prettier else None
    output_files: list[dict] = []
    errors: list[str] = []
    for i, body in enumerate(scripts):
        raw = out / f"script_{i}.js"
        raw.write_text(body)
        wc_out = out / f"script_{i}_webcrack"
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
        "available": True, "is_html": is_html, "scripts_found": len(scripts),
        "output_dir": str(out), "output_files": output_files,
        "formatter": ("prettier" if pretty else "builtin-splitter"),
        "webcrack": " ".join(wc),
        "errors": errors,
        "note": (f"{len(output_files)} cleaned file(s) — grep/read them; "
                 "content not inlined to keep it out of context"),
    }
