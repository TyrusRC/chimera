from chimera.parsers.jni_mangling import mangle, unmangle


# Spec examples (Java spec §6.1 / JNI book ch.11)
def test_mangle_simple():
    # class p.q.r.A; method f; void f() => Java_p_q_r_A_f
    assert mangle("p.q.r.A", "f") == "Java_p_q_r_A_f"


def test_mangle_underscore_in_name():
    # `_` in identifier becomes `_1`
    assert mangle("p.q.r.A", "f_g") == "Java_p_q_r_A_f_1g"


def test_mangle_with_overloaded_signature():
    # for an overloaded method, `__` + mangled descriptor is appended
    sig = "(I)V"
    out = mangle("p.q.r.A", "f", smali_sig=sig, overloaded=True)
    # `(` and `)` are stripped; `;` -> `_2`, `[` -> `_3`
    assert out == "Java_p_q_r_A_f__I"


def test_mangle_with_array_and_object_descriptor():
    sig = "([BLjava/lang/String;)V"
    out = mangle("p.A", "g", smali_sig=sig, overloaded=True)
    # [ -> _3, ; -> _2, / -> _, return type stripped (overloaded prefix)
    assert out == "Java_p_A_g___3BLjava_lang_String_2"


def test_mangle_unicode():
    out = mangle("p", "fé")
    assert out == "Java_p_f_00e9"


def test_unmangle_simple():
    assert unmangle("Java_p_q_r_A_f") == ("p/q/r/A", "f", None)


def test_unmangle_overloaded():
    cls, meth, sig = unmangle("Java_p_q_r_A_f__I")
    assert cls == "p/q/r/A"
    assert meth == "f"
    assert sig == "(I)"  # return type unknown from symbol alone
