import asyncio

from chimera.adapters.ida import IdaAdapter


def test_unavailable_when_no_idat(monkeypatch):
    monkeypatch.delenv("IDA_PATH", raising=False)
    monkeypatch.setattr("shutil.which", lambda n: None)
    assert IdaAdapter().is_available() is False


def test_available_via_ida_path(tmp_path, monkeypatch):
    fake = tmp_path / "idat64"
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    monkeypatch.setenv("IDA_PATH", str(fake))
    assert IdaAdapter().is_available() is True


def test_decompile_reads_hexrays_output(tmp_path, monkeypatch):
    binp = tmp_path / "a.bin"
    binp.write_bytes(b"\x90" * 16)
    calls = {}

    def fake_run(argv, env=None, timeout=None, **kw):
        calls["argv"] = argv
        calls["env"] = env
        with open(env["CHIMERA_IDA_OUT"], "w") as f:
            f.write("int main() { return 0; }\n")

        class R:
            returncode = 0
        return R()

    monkeypatch.setattr("subprocess.run", fake_run)
    a = IdaAdapter(idat="/opt/ida/idat64")
    r = asyncio.run(a.analyze(str(binp), {"mode": "decompile", "address": "0x401000"}))
    assert r["ok"] and r["backend"] == "ida-hexrays"
    assert "int main()" in r["code"] and r["lines"] >= 1
    assert "0x401000" not in " ".join(calls["argv"])
    assert calls["env"]["CHIMERA_IDA_ADDR"] == "0x401000"
    assert str(binp) not in " ".join(calls["argv"])


def test_decompile_empty_output_is_failure(tmp_path, monkeypatch):
    binp = tmp_path / "a.bin"
    binp.write_bytes(b"\x90")

    def fake_run(argv, env=None, timeout=None, **kw):
        open(env["CHIMERA_IDA_OUT"], "w").close()

        class R:
            returncode = 0
        return R()

    monkeypatch.setattr("subprocess.run", fake_run)
    r = asyncio.run(IdaAdapter(idat="/opt/ida/idat64").analyze(
        str(binp), {"mode": "decompile", "address": "0x1"}))
    assert r["ok"] is False and r.get("hint")


def test_decompile_timeout(tmp_path, monkeypatch):
    import subprocess
    binp = tmp_path / "a.bin"
    binp.write_bytes(b"\x90")

    def fake_run(argv, env=None, timeout=None, **kw):
        raise subprocess.TimeoutExpired(argv, timeout)

    monkeypatch.setattr("subprocess.run", fake_run)
    r = asyncio.run(IdaAdapter(idat="/opt/ida/idat64").analyze(
        str(binp), {"mode": "decompile", "address": "0x1"}))
    assert r["ok"] is False and "time" in r["error"].lower()
