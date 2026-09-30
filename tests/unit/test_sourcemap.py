import base64
import json

from chimera.unpacking import sourcemap


def _map(sources, contents):
    return json.dumps({"version": 3, "sources": sources, "sourcesContent": contents})


def test_recover_from_map_file(tmp_path):
    mp = tmp_path / "app.js.map"
    mp.write_text(_map(["src/a.js", "src/b.js"], ["A();", "B();"]))
    r = sourcemap.recover_sources(str(mp))
    assert r["ok"] and r["count"] == 2
    assert r["files"]["src/a.js"] == "A();" and r["files"]["src/b.js"] == "B();"


def test_recover_from_bundle_inline_data_url(tmp_path):
    m = _map(["x.js"], ["X();"])
    b64 = base64.b64encode(m.encode()).decode()
    bundle = tmp_path / "bundle.js"
    bundle.write_text("console.log(1);\n//# sourceMappingURL=data:application/json;base64," + b64 + "\n")
    r = sourcemap.recover_sources(str(bundle))
    assert r["ok"] and r["files"]["x.js"] == "X();"


def test_recover_from_adjacent_map(tmp_path):
    bundle = tmp_path / "main.js"
    bundle.write_text("var a=1;\n//# sourceMappingURL=main.js.map\n")
    (tmp_path / "main.js.map").write_text(_map(["y.js"], ["Y();"]))
    r = sourcemap.recover_sources(str(bundle))
    assert r["ok"] and r["files"]["y.js"] == "Y();"


def test_no_map_is_clean_failure(tmp_path):
    bundle = tmp_path / "plain.js"
    bundle.write_text("var a=1;\n")
    r = sourcemap.recover_sources(str(bundle))
    assert r["ok"] is False and "error" in r


def test_source_path_is_sanitized_against_traversal(tmp_path):
    mp = tmp_path / "e.js.map"
    mp.write_text(_map(["webpack:///../../../../etc/passwd", "webpack:///src/ok.js"],
                       ["PWNED", "ok"]))
    r = sourcemap.recover_sources(str(mp))
    assert r["ok"]
    # every recovered key is a safe relative path (no leading / or .. escape)
    for k in r["files"]:
        assert not k.startswith("/") and ".." not in k.split("/")
