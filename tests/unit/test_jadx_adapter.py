"""Unit tests for JadxAdapter CLI flag composition."""

from __future__ import annotations


async def test_jadx_passes_mapping_file_flag(tmp_path, monkeypatch):
    """When options['mapping_file'] is a path, jadx CLI gets --mappings-path."""
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
    assert "--mappings-path" in argv, argv
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
    """deobf_cache_dir is now passed via JADX_CACHE_DIR env, not a CLI flag."""
    from chimera.adapters.jadx import JadxAdapter
    apk = tmp_path / "in.apk"
    apk.write_bytes(b"PK")

    captured_argv: list[list[str]] = []
    captured_env: list[dict | None] = []

    class FakeProc:
        returncode = 0
        async def communicate(self):
            return b"", b""

    async def fake_exec(*argv, **kw):
        captured_argv.append(list(argv))
        captured_env.append(kw.get("env"))
        return FakeProc()

    import asyncio
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    adapter = JadxAdapter()
    cache_dir = tmp_path / "cache"
    await adapter.analyze(str(apk), {
        "output_dir": str(tmp_path / "out"),
        "deobf_cache_dir": str(cache_dir),
    })
    env = captured_env[0]
    assert env is not None, "expected env to be set when deobf_cache_dir is provided"
    assert env.get("JADX_CACHE_DIR") == str(cache_dir)
    # Cache directory should be created on disk for jadx to write into.
    assert cache_dir.exists()
