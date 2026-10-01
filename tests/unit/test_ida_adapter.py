import asyncio
import os
import re

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


def _fake_run_factory(decompile_out="int main() { return 0; }\n",
                      funcs_out="401000\t32\tmain\n401040\t16\tsub_401040\n",
                      disasm_out="401000  push rbp\n401001  mov rbp, rsp\n"):
    """Simulate idat: build creates the DB (input.id0); a query script is read to
    learn its templated output path + mode, and the simulated result is written
    there. Records each call's staged-script content for assertions."""
    calls = []

    def fake_run(argv, env=None, timeout=None, **kw):
        script = next(a[2:] for a in argv if a.startswith("-S")).replace("WIN:", "")
        workbin = argv[-1].replace("WIN:", "")
        keydir = os.path.dirname(workbin)
        content = open(script).read()
        calls.append({"argv": argv, "content": content, "create": "-c" in argv})
        if "save_database" in content:          # build step
            open(os.path.join(keydir, "input.id0"), "w").close()
        else:
            m = re.search(r'f?open\(r?"([^"]+)"', content)
            out = m.group(1).replace("WIN:", "")
            if "get_next_func" in content:
                open(out, "w").write(funcs_out)
            elif "GetDisasm" in content:
                open(out, "w").write(disasm_out)
            elif "decompile" in content:
                open(out, "w").write(decompile_out)
            else:
                open(out, "w").write("custom-script-output\n")

        class R:
            returncode = 0
        return R()

    return fake_run, calls


def test_decompile_reads_hexrays_output(tmp_path, monkeypatch):
    binp = tmp_path / "a.bin"
    binp.write_bytes(b"\x90" * 16)
    fake_run, calls = _fake_run_factory()
    monkeypatch.setattr("subprocess.run", fake_run)
    a = IdaAdapter(idat="/opt/ida/idat64", cache_dir=str(tmp_path / "cache"))
    r = asyncio.run(a.analyze(str(binp), {"mode": "decompile", "address": "0x401000"}))
    assert r["ok"] and r["backend"] == "ida-hexrays"
    assert "int main()" in r["code"]
    for c in calls:
        assert str(binp) not in " ".join(c["argv"])   # raw binary never on cmdline
    dec = [c for c in calls if "decompile" in c["content"]][0]
    assert "0x401000" in dec["content"]                # address templated into script


def test_idb_is_cached_across_calls(tmp_path, monkeypatch):
    binp = tmp_path / "a.bin"
    binp.write_bytes(b"\x90" * 16)
    fake_run, calls = _fake_run_factory()
    monkeypatch.setattr("subprocess.run", fake_run)
    a = IdaAdapter(idat="/opt/ida/idat64", cache_dir=str(tmp_path / "cache"))
    asyncio.run(a.analyze(str(binp), {"mode": "functions"}))
    asyncio.run(a.analyze(str(binp), {"mode": "functions"}))
    assert sum(1 for c in calls if c["create"]) == 1   # analysis ran once


def test_functions_mode_parses_list(tmp_path, monkeypatch):
    binp = tmp_path / "a.bin"
    binp.write_bytes(b"\x90" * 16)
    fake_run, _ = _fake_run_factory()
    monkeypatch.setattr("subprocess.run", fake_run)
    a = IdaAdapter(idat="/opt/ida/idat64", cache_dir=str(tmp_path / "cache"))
    r = asyncio.run(a.analyze(str(binp), {"mode": "functions"}))
    assert r["ok"] and r["count"] == 2
    assert r["functions"][0] == {"addr": "0x401000", "size": 32, "name": "main"}


def test_disasm_mode(tmp_path, monkeypatch):
    binp = tmp_path / "a.bin"
    binp.write_bytes(b"\x90" * 16)
    fake_run, calls = _fake_run_factory()
    monkeypatch.setattr("subprocess.run", fake_run)
    a = IdaAdapter(idat="/opt/ida/idat64", cache_dir=str(tmp_path / "cache"))
    r = asyncio.run(a.analyze(str(binp), {"mode": "disasm", "address": "0x401000"}))
    assert r["ok"] and "push rbp" in r["disasm"]
    dis = [c for c in calls if "GetDisasm" in c["content"]][0]
    assert "0x401000" in dis["content"]


def test_script_mode(tmp_path, monkeypatch):
    binp = tmp_path / "a.bin"
    binp.write_bytes(b"\x90" * 16)
    scriptp = tmp_path / "my.idc"
    scriptp.write_text('static main(){ auto f=fopen("__CHIMERA_OUT__","w"); fclose(f); qexit(0); }\n')
    fake_run, _ = _fake_run_factory()
    monkeypatch.setattr("subprocess.run", fake_run)
    a = IdaAdapter(idat="/opt/ida/idat64", cache_dir=str(tmp_path / "cache"))
    r = asyncio.run(a.analyze(str(binp), {"mode": "script", "script": str(scriptp)}))
    assert r["ok"] and "custom-script-output" in r["output"]


def test_missing_db_is_clear_failure(tmp_path, monkeypatch):
    binp = tmp_path / "a.bin"
    binp.write_bytes(b"\x90" * 16)

    def fake_run(argv, env=None, timeout=None, **kw):  # never creates the DB
        class R:
            returncode = 0
        return R()

    monkeypatch.setattr("subprocess.run", fake_run)
    a = IdaAdapter(idat="/opt/ida/idat64", cache_dir=str(tmp_path / "cache"))
    r = asyncio.run(a.analyze(str(binp), {"mode": "functions"}))
    assert r["ok"] is False and "database" in r["error"]


def test_windows_idat_translates_paths(tmp_path, monkeypatch):
    from chimera.adapters import ida as idamod
    binp = tmp_path / "a.bin"
    binp.write_bytes(b"\x90" * 8)
    monkeypatch.setattr(idamod, "to_windows_path", lambda p: "WIN:" + p)
    fake_run, calls = _fake_run_factory()
    monkeypatch.setattr("subprocess.run", fake_run)
    a = IdaAdapter(idat="/opt/ida/idat64.exe", cache_dir=str(tmp_path / "cache"))
    r = asyncio.run(a.analyze(str(binp), {"mode": "functions"}))
    assert r["ok"] and r["count"] == 2
    q = [c for c in calls if "get_next_func" in c["content"]][0]
    assert any(a.startswith("-SWIN:") for a in q["argv"])   # script path translated
    assert 'fopen("WIN:' in q["content"]                    # out path translated + baked
