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


def _write_flaredle(tmp_path):
    """Reconstruct Flare-On 11 ch.1 shape: index.html -> script.js -> words.js."""
    (tmp_path / "index.html").write_text(
        '<html><head><script src="script.js" type="module"></script>'
        '<script src="https://cdn.example/toastr.js"></script></head><body></body></html>')
    (tmp_path / "script.js").write_text(
        'import { WORDS } from "./words.js";\n'
        'import toastr from "toastr";\n'
        'const CORRECT_GUESS = 57;\n'
        'let rightGuessString = WORDS[CORRECT_GUESS];\n')
    words = ["aardvark"] * 57 + ["flareonisallaboutcats", "zulu"]
    (tmp_path / "words.js").write_text(
        "export const WORDS = [" + ", ".join(f'"{w}"' for w in words) + "];\n")
    return tmp_path


def test_collect_local_scripts_follows_src_and_imports(tmp_path):
    _write_flaredle(tmp_path)
    files, skipped = js_deobf.collect_local_scripts(tmp_path / "index.html")
    names = [f.name for f in files]
    assert names == ["script.js", "words.js"]           # src root -> import edge
    assert any("toastr" in s for s in skipped)          # bare pkg skipped
    assert any(s.startswith("https://") for s in skipped)  # remote src skipped


def test_resolve_const_index_reads_array_element(tmp_path):
    _write_flaredle(tmp_path)
    js = (tmp_path / "words.js").read_text()
    assert js_deobf.resolve_const_index(js, "WORDS", 57) == "flareonisallaboutcats"
    assert js_deobf.resolve_const_index(js, "WORDS", 99999) is None  # OOB
    assert js_deobf.resolve_const_index(js, "NOPE", 0) is None       # unknown name


def test_deobfuscate_resolve_solves_flaredle_without_node(tmp_path, monkeypatch):
    _write_flaredle(tmp_path)
    monkeypatch.setattr(js_deobf, "node_tool_cmd", lambda tool: None)  # no node at all
    r = js_deobf.deobfuscate(str(tmp_path / "index.html"), resolve="WORDS[57]")
    assert r["available"] and r["resolved"]["value"] == "flareonisallaboutcats"
    # the flag is the resolved word + the domain, matching the challenge
    assert r["resolved"]["value"] + "@flare-on.com" == "flareonisallaboutcats@flare-on.com"


def test_split_array_literal_respects_quotes_and_nesting():
    js = 'x = ["a,b", [1, 2], "c", {"k": 3}];'
    elems = js_deobf._split_array_literal(js, js.index("["))
    assert elems == ['"a,b"', "[1, 2]", '"c"', '{"k": 3}']
    assert js_deobf._as_scalar(elems[0]) == "a,b"        # comma inside string kept
    assert js_deobf._as_scalar(elems[1]) is None         # nested array not a scalar


def test_is_local_spec_classifies_specifiers():
    assert js_deobf._is_local_spec("./words.js")
    assert js_deobf._is_local_spec("/js/app.js")
    assert not js_deobf._is_local_spec("https://cdn/x.js")
    assert not js_deobf._is_local_spec("//cdn/x.js")
    assert not js_deobf._is_local_spec("toastr")          # bare package


def test_node_tool_cmd_prefers_path_then_npx(monkeypatch):
    monkeypatch.setattr(js_deobf.shutil, "which",
                        lambda t: "/usr/bin/webcrack" if t == "webcrack" else None)
    assert js_deobf.node_tool_cmd("webcrack") == ["webcrack"]
    monkeypatch.setattr(js_deobf.shutil, "which",
                        lambda t: "/usr/bin/npx" if t == "npx" else None)
    assert js_deobf.node_tool_cmd("webcrack") == ["npx", "--yes", "webcrack"]
    monkeypatch.setattr(js_deobf.shutil, "which", lambda t: None)
    assert js_deobf.node_tool_cmd("webcrack") is None
