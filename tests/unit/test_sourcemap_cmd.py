import json

from click.testing import CliRunner

from chimera.cli import main


def test_sourcemap_cli_writes_sources(tmp_path):
    mp = tmp_path / "app.js.map"
    mp.write_text(json.dumps({"version": 3, "sources": ["src/a.js"],
                              "sourcesContent": ["console.log('a');"]}))
    out = tmp_path / "recovered"
    r = CliRunner().invoke(main, ["sourcemap", str(mp), "-o", str(out)])
    assert r.exit_code == 0
    assert (out / "src/a.js").read_text() == "console.log('a');"


def test_sourcemap_cli_no_map_errors(tmp_path):
    bundle = tmp_path / "plain.js"
    bundle.write_text("var a=1;\n")
    r = CliRunner().invoke(main, ["sourcemap", str(bundle)])
    assert r.exit_code != 0
