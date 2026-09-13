"""Detection of .NET CIL method-body encryption from decompiled C# (backdoor)."""
from __future__ import annotations

from chimera.dotnet.obfuscation import scan_dotnet_obfuscation

# A readable stub method — valid CIL — that forwards to an invalid-CIL method
# and catches the InvalidProgramException the runtime throws (the FO 'backdoor'
# flare_XX pattern).
_STUB = """
public static string flare_23(string a)
{
    string result;
    try
    {
        result = FLARE15.flared_23(a);
    }
    catch (InvalidProgramException e)
    {
        result = (string)FLARE15.flare_71(e, new object[] { a }, FLARE15.AAA, FLARE15.BBB);
    }
    return result;
}
"""

# The reconstruction engine (flare_71): recovers the faulty method from the
# exception and rebuilds it as a DynamicMethod.
_ENGINE = """
public static object flare_71(InvalidProgramException e, object[] args, Dictionary<uint, int> m, byte[] b)
{
    StackTrace stackTrace = new StackTrace(e);
    int metadataToken = stackTrace.GetFrame(0).GetMethod().MetadataToken;
    Module module = typeof(Program).Module;
    MethodInfo methodInfo = (MethodInfo)module.ResolveMethod(metadataToken);
    DynamicMethod dynamicMethod = new DynamicMethod("", methodInfo.ReturnType, array, declaringType, true);
    DynamicILInfo dynamicILInfo = dynamicMethod.GetDynamicILInfo();
    SignatureHelper localVarSigHelper = SignatureHelper.GetLocalVarSigHelper();
    dynamicILInfo.SetLocalSignature(signature);
    dynamicILInfo.SetCode(b, methodBody.MaxStackSize);
    return dynamicMethod.Invoke(null, args);
}
"""

_CLEAN = """
public static int Add(int a, int b)
{
    try { return checked(a + b); }
    catch (OverflowException) { return -1; }
}
public sealed class Widget { public string Name { get; set; } }
"""


def test_detects_method_body_encryption():
    r = scan_dotnet_obfuscation([_STUB, _ENGINE])
    assert r.detected
    assert r.technique == "method-body-encryption"
    assert r.invalid_program_catches == 1
    assert r.dynamic_il_reconstruction
    assert r.token_from_exception
    assert r.note and "PARTIAL" in r.note


def test_swarm_of_stubs_alone_is_enough():
    # Many stubs but the engine method wasn't in this shard: >=2 catches still
    # confirms the family (every protected method compiles to one).
    r = scan_dotnet_obfuscation([_STUB, _STUB.replace("flare_23", "flare_24")])
    assert r.detected
    assert r.invalid_program_catches == 2
    assert not r.dynamic_il_reconstruction


def test_single_legit_catch_without_engine_is_not_flagged():
    lone = """
    void f() { try { g(); } catch (InvalidProgramException) { throw; } }
    """
    r = scan_dotnet_obfuscation([lone])
    assert not r.detected
    assert r.technique is None


def test_clean_assembly_is_not_flagged():
    r = scan_dotnet_obfuscation([_CLEAN])
    assert not r.detected
    assert r.invalid_program_catches == 0


def test_handles_empty_and_none_texts():
    r = scan_dotnet_obfuscation([None, "", _CLEAN])
    assert not r.detected
