"""The REPL bootstrap script must exist and expose rpc.exports.eval."""
from pathlib import Path

import chimera.frida_scripts as fs


def test_repl_script_file_exists():
    path = Path(fs.__file__).parent / "_repl.js"
    assert path.exists()


def test_repl_script_exposes_rpc_eval():
    path = Path(fs.__file__).parent / "_repl.js"
    text = path.read_text(encoding="utf-8")
    assert "rpc.exports" in text
    assert "eval" in text


def test_repl_script_not_in_registry():
    # _repl.js has no // chimera-frida-script header, so list_scripts() skips it.
    ids = [s.id for s in fs.list_scripts()]
    assert "_repl" not in ids
    assert "repl" not in ids
