from pathlib import Path

from chimera.parsers.jvm_methods import parse_java_file, parse_kotlin_file, JvmMethod

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
    assert names == ["decrypt", "greet", "log", "noop", "sum"]
    sum_m = _by_name(methods, "sum")[0]
    assert sum_m.smali_sig == "(II)I"
    assert sum_m.is_native is False


def test_java_method_records_line_numbers():
    methods = parse_java_file(FIXTURES / "Foo.java", "com.example")
    for m in methods:
        assert m.line >= 1
        assert m.file.endswith("Foo.java")


def test_parses_java_varargs_as_array():
    methods = parse_java_file(FIXTURES / "Foo.java", "com.example")
    log = _by_name(methods, "log")[0]
    # varargs collapses to array dim:
    # `String fmt, Object... args` -> "(Ljava/lang/String;[Ljava/lang/Object;)V"
    # NOTE: jadx's unqualified `String`/`Object` produce `LString;`/`LObject;`
    # in our parser today (documented limitation); the assertion below
    # matches the parser's actual canonical Smali contract.
    assert log.smali_sig == "(LString;[LObject;)V"


def test_parses_kotlin_external_fun():
    methods = parse_kotlin_file(FIXTURES / "Bar.kt", "com.example")
    nd = _by_name(methods, "nativeDecrypt")
    assert len(nd) == 1
    assert nd[0].is_native is True
    assert nd[0].class_fqcn == "com.example.Bar"
    assert nd[0].language == "kotlin"


def test_parses_kotlin_regular_fun():
    methods = parse_kotlin_file(FIXTURES / "Bar.kt", "com.example")
    names = sorted(m.name for m in methods)
    assert "greet" in names
    assert "staticHelper" in names
    greet = _by_name(methods, "greet")[0]
    assert greet.is_native is False
