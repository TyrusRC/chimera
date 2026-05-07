from pathlib import Path

from chimera.parsers.jvm_methods import parse_java_file, JvmMethod

FIXTURES = Path(__file__).parent.parent / "fixtures" / "jvm_methods"


def _by_name(methods, name):
    return [m for m in methods if m.name == name]


def test_parses_java_native_method():
    methods = parse_java_file(FIXTURES / "Foo.java", "com.example")
    decrypt = _by_name(methods, "decrypt")
    assert len(decrypt) == 1
    m = decrypt[0]
    assert m.is_native is True
    assert m.class_fqcn == "com.example.Foo"
    assert m.smali_sig == "([B)I"
    assert m.language == "java"


def test_parses_java_regular_methods():
    methods = parse_java_file(FIXTURES / "Foo.java", "com.example")
    names = sorted(m.name for m in methods)
    assert names == ["decrypt", "greet", "noop", "sum"]
    sum_m = _by_name(methods, "sum")[0]
    assert sum_m.smali_sig == "(II)I"
    assert sum_m.is_native is False


def test_java_method_records_line_numbers():
    methods = parse_java_file(FIXTURES / "Foo.java", "com.example")
    for m in methods:
        assert m.line >= 1
        assert m.file.endswith("Foo.java")
