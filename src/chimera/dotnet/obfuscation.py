"""Detect CIL-level method-body obfuscation on a .NET assembly.

A whole family of .NET protectors (this challenge's custom obfuscator,
ConfuserEx "method encryption" derivatives, .NET Reactor, many CTF samples)
hides a method's real body by storing **invalid CIL** in it. At runtime the
invalid body throws ``InvalidProgramException``; a stub method catches exactly
that, recovers the faulty method's metadata token from the exception's
``StackTrace``, decrypts the real CIL (often RC4/XOR'd, sometimes stashed in a
non-standard PE section named after a hash of the method), and rebuilds it as a
``DynamicMethod`` via ``DynamicILInfo.SetCode`` before invoking it.

The trap for a triage tool: a decompiler (ILSpy/dnSpy) silently decompiles only
the ~half of methods whose CIL is valid — the readable stubs — and the real
logic never appears. chimera ingests that partial C# with no warning, so the
analyst trusts an assembly that is mostly hidden. This scanner reads the same
decompiled C# chimera already produces and flags the obfuscation signature, so
recon reports "this is CIL-obfuscated; ILSpy output is PARTIAL; the real bodies
are runtime-reconstructed" and points at the follow-through (decrypt the
encrypted bodies, or run the sample and let it rebuild them).

Text-only and dependency-free — it works off the decompiler output, so it needs
no .NET metadata library. Recognition, not deobfuscation: fully rebuilding the
bodies is a per-sample AsmResolver/dnlib job (or a dynamic solve).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

# The invalid-CIL tell: a handler catching InvalidProgramException. Legitimate
# code virtually never does this — it is thrown only by a malformed method body.
_INVALID_PROGRAM_CATCH = re.compile(
    r"catch\s*\(\s*(?:System\.)?InvalidProgramException\b")
# Runtime IL (re)construction engine: the APIs that build+run a method body from
# raw bytes at runtime.
_DYNAMIC_IL_APIS = (
    "GetDynamicILInfo", "DynamicILInfo", "SetLocalSignature",
    "SignatureHelper", "DynamicMethod",
)
# Recovering the faulty method from the thrown exception's stack trace.
_TOKEN_FROM_EXCEPTION = ("StackTrace", "ResolveMethod", "MetadataToken")


@dataclass
class DotNetObfuscationReport:
    detected: bool = False
    technique: str | None = None            # "method-body-encryption"
    invalid_program_catches: int = 0
    dynamic_il_reconstruction: bool = False
    token_from_exception: bool = False
    signals: list[str] = field(default_factory=list)
    note: str | None = None

    def to_dict(self) -> dict:
        return {
            "detected": self.detected, "technique": self.technique,
            "invalid_program_catches": self.invalid_program_catches,
            "dynamic_il_reconstruction": self.dynamic_il_reconstruction,
            "token_from_exception": self.token_from_exception,
            "signals": self.signals, "note": self.note,
        }


def scan_dotnet_obfuscation(texts: Iterable[str]) -> DotNetObfuscationReport:
    """Scan decompiled C# for the method-body-encryption signature.

    `texts` is the per-type/per-file decompiled source (what ILSpy emits and
    the pipeline already caches). Returns a report; `detected` is set only when
    the invalid-CIL catch pattern coincides with the runtime-reconstruction
    engine, so a lone legitimate catch does not false-positive.
    """
    r = DotNetObfuscationReport()
    seen_dynamic: set[str] = set()
    seen_token: set[str] = set()

    for text in texts:
        if not text:
            continue
        r.invalid_program_catches += len(_INVALID_PROGRAM_CATCH.findall(text))
        for api in _DYNAMIC_IL_APIS:
            if api in text:
                seen_dynamic.add(api)
        for tok in _TOKEN_FROM_EXCEPTION:
            if tok in text:
                seen_token.add(tok)

    r.dynamic_il_reconstruction = len(seen_dynamic) >= 2
    r.token_from_exception = len(seen_token) == len(_TOKEN_FROM_EXCEPTION)

    # A single InvalidProgramException catch is (rarely) legitimate; the family
    # is confirmed by the reconstruction engine, OR by the swarm of stubs that
    # every protected method compiles down to (many identical catches).
    r.detected = r.invalid_program_catches > 0 and (
        r.dynamic_il_reconstruction or r.invalid_program_catches >= 2)

    if not r.detected:
        return r

    r.technique = "method-body-encryption"
    if r.invalid_program_catches:
        r.signals.append(
            f"{r.invalid_program_catches} InvalidProgramException catch handler(s) "
            "(invalid-CIL method bodies reconstructed at runtime)")
    if r.dynamic_il_reconstruction:
        r.signals.append(
            "DynamicMethod/DynamicILInfo.SetCode — runtime CIL (re)construction engine")
    if r.token_from_exception:
        r.signals.append(
            "StackTrace(e)+ResolveMethod(MetadataToken) — recovers the faulty method from the exception")
    r.note = (
        "Decompiler output is PARTIAL: only the valid-CIL stub methods decompile; "
        "the real method bodies are invalid CIL rebuilt at runtime. Recover them "
        "per-sample (AsmResolver/dnlib) or dynamically (run the sample and dump the "
        "reconstructed body). Encrypted bodies are often RC4/XOR'd — check "
        "non-standard / high-entropy PE sections and decrypt with decrypt_blob.")
    return r
