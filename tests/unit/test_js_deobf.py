"""js-deobf: HTML <script> extraction, line-splitting, and graceful degrade.

The webcrack/prettier passes are external (node); these tests cover the
dependency-free logic and the "tool absent" path without needing node.
"""
from __future__ import annotations

from chimera.unpacking import js_deobf


def test_extract_scripts_html_takes_inline_skips_src():
    html = ('<html><head><script src="ext.js"></script></head>'
            '<body><script>var flag = 1; foo();</script>'
            '<script>bar();</script></body></html>')
    scripts = js_deobf.extract_scripts(html, is_html=True)
    assert scripts == ["var flag = 1; foo();", "bar();"]


def test_extract_scripts_plain_js_returns_whole_text():
    assert js_deobf.extract_scripts("a=1;b=2;", is_html=False) == ["a=1;b=2;"]


def test_fallback_split_breaks_only_long_lines():
    short = "var a = 1;"
    long = "x();" * 100  # 400 chars, one line
    out = js_deobf._fallback_split(short + "\n" + long, max_col=50)
    lines = out.splitlines()
    assert short in lines                     # short line untouched
    assert len(lines) > 2                      # long line was split
    assert all(len(l) <= 60 for l in lines)    # each chunk ends near a ; boundary


def test_deobfuscate_missing_file():
    r = js_deobf.deobfuscate("/no/such/file.js")
    assert r["available"] and "not found" in r["error"]


def test_deobfuscate_degrades_without_webcrack(tmp_path, monkeypatch):
    f = tmp_path / "a.js"
    f.write_text("var x = 1;")
    monkeypatch.setattr(js_deobf, "node_tool_cmd", lambda tool: None)
    r = js_deobf.deobfuscate(str(f))
    assert r["available"] is False and "webcrack" in r["error"]


def test_node_tool_cmd_prefers_path_then_npx(monkeypatch):
    monkeypatch.setattr(js_deobf.shutil, "which",
                        lambda t: "/usr/bin/webcrack" if t == "webcrack" else None)
    assert js_deobf.node_tool_cmd("webcrack") == ["webcrack"]
    monkeypatch.setattr(js_deobf.shutil, "which",
                        lambda t: "/usr/bin/npx" if t == "npx" else None)
    assert js_deobf.node_tool_cmd("webcrack") == ["npx", "--yes", "webcrack"]
    monkeypatch.setattr(js_deobf.shutil, "which", lambda t: None)
    assert js_deobf.node_tool_cmd("webcrack") is None
