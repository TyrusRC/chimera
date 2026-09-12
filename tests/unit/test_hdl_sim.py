"""hdl-sim: Verilog simulation oracle (iverilog/vvp).

Tool-resolution + graceful-degrade run without iverilog; the compile+run path
runs only where iverilog/vvp are on PATH (skipped otherwise).
"""
from __future__ import annotations

import pytest

from chimera.dynamic import hdl_sim as H


def test_unavailable_when_tools_missing():
    r = H.hdl_sim(["/tmp/x.v"], iverilog="/no/such/iverilog", vvp="/no/such/vvp")
    assert r["available"] is False and "iverilog" in r["error"]


def test_resolve_explicit_path(tmp_path):
    f = tmp_path / "iverilog"
    f.write_text("#!/bin/sh\n")
    assert H._resolve(str(f)) == str(f)
    assert H._resolve(str(tmp_path / "missing")) is None


def test_missing_sources_reported(tmp_path, monkeypatch):
    # Pretend the toolchain resolves so we reach source validation.
    monkeypatch.setattr(H, "_resolve", lambda t: "/usr/bin/" + t.rsplit("/", 1)[-1])
    r = H.hdl_sim([str(tmp_path / "nope.v")])
    assert r["available"] and "not found" in r["error"]

    r2 = H.hdl_sim([])
    assert r2["available"] and "no source" in r2["error"]


@pytest.mark.skipif(not H.iverilog_available(), reason="iverilog/vvp not installed")
def test_compile_and_run_captures_display(tmp_path):
    v = tmp_path / "tb.v"
    v.write_text(
        "module tb;\n"
        "  initial begin\n"
        "    $display(\"chimera-hdl-ok\");\n"
        "    $finish;\n"
        "  end\n"
        "endmodule\n")
    r = H.hdl_sim([str(v)], top="tb", workdir=str(tmp_path))
    assert r["compiled"] and r["returncode"] == 0
    assert "chimera-hdl-ok" in r["stdout"]
