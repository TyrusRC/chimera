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


class _StubCache:
    def __init__(self, blobs):
        self._blobs = blobs

    def get_json(self, sha, key):
        return self._blobs.get((sha, key))


def test_collect_native_exports_from_cache():
    from chimera.pipelines.cross_layer import collect_native_exports_from_cache
    cache = _StubCache({
        ("d" * 64, "r2_libnative.so"): {
            "functions": [
                {"name": "Java_com_example_Foo_decrypt", "vaddr": 0x12340},
                {"name": "fclose", "vaddr": 0x99},
            ],
        },
    })
    out = collect_native_exports_from_cache(cache, "d" * 64, ["r2_libnative.so"])
    assert out == {"libnative.so": [("Java_com_example_Foo_decrypt", "0x12340")]}


def test_collect_native_exports_prefers_explicit_exports_field():
    # When the cached blob carries an `exports` list, use it directly and
    # ignore the `functions` fallback. This is the path r2 takes once it
    # surfaces an `iEj`-derived export list.
    from chimera.pipelines.cross_layer import collect_native_exports_from_cache
    cache = _StubCache({
        ("e" * 64, "r2_libfoo.so"): {
            "exports": [
                {"name": "Java_p_A_g", "vaddr": 0xABCD0},
                {"name": "_init", "vaddr": 0x10},
            ],
            "functions": [
                {"name": "Java_should_be_ignored", "vaddr": 0xDEAD},
            ],
        },
    })
    out = collect_native_exports_from_cache(cache, "e" * 64, ["r2_libfoo.so"])
    assert out == {"libfoo.so": [("Java_p_A_g", "0xabcd0")]}


def test_link_jvm_callsites_emits_edges():
    from chimera.parsers.jvm_methods import JvmMethod
    from chimera.pipelines.cross_layer import link_jvm_callsites
    m = _make_model()
    # add a non-native caller to the model
    m.add_function(FunctionInfo(
        address="jvm:com.example.Foo::caller()V",
        name="caller", original_name="com.example.Foo.caller",
        language="java", classification="unknown", layer="jvm",
        source_backend="jadx",
        metadata={"is_native": False, "class_fqcn": "com.example.Foo",
                  "smali_sig": "()V"},
    ))
    callsites = [
        type("CS", (), {
            "caller": JvmMethod(
                class_fqcn="com.example.Foo", name="caller",
                smali_sig="()V", is_native=False,
                file="X.java", line=10, language="java",
            ),
            "callee_name": "decrypt",
            "line": 11,
        })(),
    ]
    n = link_jvm_callsites(m, callsites)
    assert n == 1
    callees = m.get_callees("jvm:com.example.Foo::caller()V")
    assert any(c.address == "jvm:com.example.Foo::decrypt([B)I" for c in callees)
