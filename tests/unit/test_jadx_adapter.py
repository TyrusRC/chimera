"""Unit tests for JadxAdapter CLI flag composition."""

from __future__ import annotations


async def test_jadx_passes_mapping_file_flag(tmp_path, monkeypatch):
    """When options['mapping_file'] is a path, jadx CLI gets --mapping-file."""
    from chimera.adapters.jadx import JadxAdapter

    mapping = tmp_path / "mapping.txt"
    mapping.write_text("x -> a:\n")
    apk = tmp_path / "in.apk"
    apk.write_bytes(b"PK")

    captured: list[list[str]] = []

    class FakeProc:
        returncode = 0
        async def communicate(self):
            return b"", b""

    async def fake_exec(*argv, **kw):
        captured.append(list(argv))
        return FakeProc()

    import asyncio
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    adapter = JadxAdapter()
    await adapter.analyze(str(apk), {
        "output_dir": str(tmp_path / "out"),
        "mapping_file": str(mapping),
    })
    argv = captured[0]
    assert "--mapping-file" in argv, argv
    assert str(mapping) in argv


async def test_jadx_passes_kotlin_flags_when_kotlin_aware(tmp_path, monkeypatch):
    from chimera.adapters.jadx import JadxAdapter
    apk = tmp_path / "in.apk"
    apk.write_bytes(b"PK")

    captured: list[list[str]] = []

    class FakeProc:
        returncode = 0
        async def communicate(self):
            return b"", b""

    async def fake_exec(*argv, **kw):
        captured.append(list(argv))
        return FakeProc()

    import asyncio
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    adapter = JadxAdapter()
    await adapter.analyze(str(apk), {
        "output_dir": str(tmp_path / "out"),
        "kotlin_aware": True,
    })
    argv = captured[0]
    assert "--use-kotlin-methods-for-var-names" in argv, argv
    assert "apply" in argv
    assert "--rename-flags" in argv
    i = argv.index("--rename-flags")
    assert argv[i + 1] == "valid,printable"


async def test_jadx_no_kotlin_flags_when_not_kotlin_aware(tmp_path, monkeypatch):
    from chimera.adapters.jadx import JadxAdapter
    apk = tmp_path / "in.apk"
    apk.write_bytes(b"PK")

    captured: list[list[str]] = []

    class FakeProc:
        returncode = 0
        async def communicate(self):
            return b"", b""

    async def fake_exec(*argv, **kw):
        captured.append(list(argv))
        return FakeProc()

    import asyncio
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    adapter = JadxAdapter()
    await adapter.analyze(str(apk), {"output_dir": str(tmp_path / "out")})
    argv = captured[0]
    assert "--use-kotlin-methods-for-var-names" not in argv
    assert "--rename-flags" not in argv


async def test_jadx_passes_deobf_cache_dir(tmp_path, monkeypatch):
    from chimera.adapters.jadx import JadxAdapter
    apk = tmp_path / "in.apk"
    apk.write_bytes(b"PK")

    captured: list[list[str]] = []

    class FakeProc:
        returncode = 0
        async def communicate(self):
            return b"", b""

    async def fake_exec(*argv, **kw):
        captured.append(list(argv))
        return FakeProc()

    import asyncio
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    adapter = JadxAdapter()
    await adapter.analyze(str(apk), {
        "output_dir": str(tmp_path / "out"),
        "deobf_cache_dir": str(tmp_path / "cache"),
    })
    argv = captured[0]
    assert "--deobf-cache" in argv
    j = argv.index("--deobf-cache")
    assert "cache" in argv[j + 1]
