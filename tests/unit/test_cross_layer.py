from pathlib import Path

from chimera.model.binary import (
    Architecture, BinaryFormat, BinaryInfo, Framework, Platform,
)
from chimera.model.function import FunctionInfo
from chimera.model.program import UnifiedProgramModel
from chimera.pipelines.cross_layer import link_jni_static, JniLinkResult


def _make_model():
    bi = BinaryInfo(
        sha256="c" * 64, path=Path("/tmp/y.apk"),
        format=BinaryFormat.APK, platform=Platform.ANDROID,
        arch=Architecture.ARM64, framework=Framework.NATIVE, size_bytes=1,
    )
    m = UnifiedProgramModel(bi)
    m.add_function(FunctionInfo(
        address="jvm:com.example.Foo::decrypt([B)I",
        name="decrypt", original_name="com.example.Foo.decrypt",
        language="java", classification="native", layer="jvm",
        source_backend="jadx",
        metadata={"is_native": True, "class_fqcn": "com.example.Foo",
                  "smali_sig": "([B)I"},
    ))
    m.add_function(FunctionInfo(
        address="0x12340", name="Java_com_example_Foo_decrypt",
        original_name="Java_com_example_Foo_decrypt",
        language="c", classification="unknown", layer="native",
        source_backend="r2",
    ))
    return m


def test_link_jni_static_emits_edge():
    m = _make_model()
    result = link_jni_static(m, native_exports={"libnative.so": [
        ("Java_com_example_Foo_decrypt", "0x12340"),
    ]})
    assert isinstance(result, JniLinkResult)
    assert result.static_edges == 1
    assert result.unresolved == 0
    callees = m.get_callees("jvm:com.example.Foo::decrypt([B)I")
    assert len(callees) == 1
    assert callees[0].address == "0x12340"


def test_link_jni_static_unresolved_native_method():
    m = _make_model()
    result = link_jni_static(m, native_exports={"libnative.so": []})
    assert result.static_edges == 0
    assert result.unresolved == 1
