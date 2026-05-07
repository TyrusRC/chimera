from pathlib import Path

from chimera.model.binary import (
    Architecture, BinaryFormat, BinaryInfo, Framework, Platform,
)
from chimera.model.program import UnifiedProgramModel
from chimera.pipelines.jvm_ingest import ingest_jadx_methods


def _make_model():
    bi = BinaryInfo(
        sha256="b" * 64, path=Path("/tmp/x.apk"),
        format=BinaryFormat.APK, platform=Platform.ANDROID,
        arch=Architecture.DEX, framework=Framework.NATIVE, size_bytes=1,
    )
    return UnifiedProgramModel(bi)


def test_ingest_methods_produces_function_info(tmp_path):
    src = tmp_path / "sources" / "com" / "example"
    src.mkdir(parents=True)
    (src / "Foo.java").write_text(
        "package com.example;\n"
        "public class Foo {\n"
        "  public native int decrypt(byte[] data);\n"
        "  public void noop() {}\n"
        "}\n"
    )
    model = _make_model()
    added = ingest_jadx_methods(model, tmp_path / "sources")
    assert added == 2
    decrypt_addr = "jvm:com.example.Foo::decrypt([B)I"
    f = model.get_function(decrypt_addr)
    assert f is not None
    assert f.layer == "jvm"
    assert f.classification == "native"
    assert f.metadata["is_native"] is True
    assert f.metadata["file"].endswith("Foo.java")


def test_ingest_methods_respects_max_methods(tmp_path):
    src = tmp_path / "sources" / "com" / "example"
    src.mkdir(parents=True)
    body = "package com.example;\npublic class Foo {\n"
    for i in range(20):
        body += f"  public void m{i}() {{}}\n"
    body += "}\n"
    (src / "Foo.java").write_text(body)
    model = _make_model()
    added = ingest_jadx_methods(model, tmp_path / "sources", max_methods=5)
    assert added == 5
