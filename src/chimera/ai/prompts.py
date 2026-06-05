"""Prompt templates for the three analyst-facing AI workflows.

Kept in one module so prompt drift is reviewable in a single diff. Each
helper returns `(system, user)` strings ready for `AIClient.complete`.

Design notes:
- Decompiled code may contain placeholder names (FUN_xxxxx, DAT_xxxxx,
  iVar1). We pass the code through verbatim — the post-processor has
  already substituted what it can; the LLM should reason about what it
  sees, not what it wishes it saw.
- Outputs are kept short by capping max_tokens at the call site, not in
  the prompt — easier to tune empirically.
- We deliberately avoid asking for JSON for explain/comment; analysts read
  the prose directly. `suggest_name` is the only one with a strict shape.
"""

from __future__ import annotations

ANALYST_PERSONA = (
    "You are a senior reverse engineer assisting another analyst. "
    "Be concise, technical, and grounded — never speculate beyond what the "
    "code shows. If you're unsure, say so explicitly."
)


def explain_prompt(decomp: str, *, function_name: str = "", address: str = "") -> tuple[str, str]:
    header = []
    if function_name:
        header.append(f"function: {function_name}")
    if address:
        header.append(f"address: {address}")
    head = " | ".join(header) if header else "(no metadata)"
    user = (
        f"Explain what this function does. Keep it to 4-8 sentences.\n\n"
        f"{head}\n\n"
        f"```c\n{decomp}\n```"
    )
    return ANALYST_PERSONA, user


def rename_prompt(decomp: str, *, current_name: str = "") -> tuple[str, str]:
    user = (
        "Suggest a short snake_case name (max 40 chars) that captures what "
        "this function does. Output ONLY the name on a single line — no "
        "quotes, no prose, no markdown.\n\n"
        f"Current name: {current_name or '(none)'}\n\n"
        f"```c\n{decomp}\n```"
    )
    return ANALYST_PERSONA, user


def comment_prompt(decomp: str, *, line: int = 0) -> tuple[str, str]:
    line_hint = f"line {line}" if line else "the function as a whole"
    user = (
        f"Write a one-sentence comment for {line_hint}. Output ONLY the "
        "sentence — no quotes, no \"//\", no markdown.\n\n"
        f"```c\n{decomp}\n```"
    )
    return ANALYST_PERSONA, user


def refine_decomp_prompt(
    pseudo_c: str,
    *,
    function_name: str = "",
    address: str = "",
) -> tuple[str, str]:
    """Refine raw Ghidra/r2 pseudo-C into readable code.

    Models the LLM4Decompile-V2 workflow (EMNLP 2024 / arXiv 2505.12668):
    instead of decompiling from raw assembly, we ask the LLM to clean up
    decompiler output — rename `iVar1`/`uVar2`/`DAT_xxxxx`, replace
    `FUN_xxxxx` with descriptive call placeholders, recover obvious
    string-literal references, and re-shape obviously-rewritten control
    flow back into idiomatic C. The model is told NOT to invent
    semantics beyond what the input shows.
    """
    header = []
    if function_name:
        header.append(f"function: {function_name}")
    if address:
        header.append(f"address: {address}")
    head = " | ".join(header) if header else "(no metadata)"
    sys_p = (
        ANALYST_PERSONA + " You are refining decompiler output. NEVER "
        "invent semantics, calls, or variables the input doesn't already "
        "show — only clean up what's there."
    )
    user = (
        "Refine the following pseudo-C into readable C, preserving exact "
        "semantics. Rules:\n"
        "  - Rename placeholders (iVar1, uVar2, DAT_xxxxx, FUN_xxxxx) to "
        "    meaningful names ONLY when the meaning is unambiguous from "
        "    context; otherwise keep the placeholder.\n"
        "  - Replace obvious string-literal addresses with their inferred "
        "    string IF the original has a hint (e.g. comment, /* str */).\n"
        "  - Tighten obviously-rewritten control flow (gotos → loops) only "
        "    when the transformation is provably semantics-preserving.\n"
        "  - Output ONLY the refined C code between ```c fences — no prose, "
        "    no commentary, no diff markers.\n\n"
        f"{head}\n\n"
        f"Input:\n```c\n{pseudo_c}\n```"
    )
    return sys_p, user


def refine_decomp_fix_prompt(
    refined_code: str,
    compiler_errors: str,
    *,
    function_name: str = "",
) -> tuple[str, str]:
    """Ask the model to fix syntax errors in already-refined pseudo-C.

    Used by the DecLLM-style recompile gate (Wong et al., ISSTA 2025):
    after `refine_decomp_prompt` produces a candidate, we feed it to
    `gcc -fsyntax-only`; if the compiler rejects it, we send the errors
    back to the model for one retry round. Beyond one retry the cost/
    benefit tips toward returning the earlier candidate unchanged.
    """
    sys_p = (
        ANALYST_PERSONA + " You are repairing C code that another pass of "
        "this model produced. ONLY fix the listed compiler errors — do not "
        "rename, re-shape, or change semantics."
    )
    head = f"function: {function_name}" if function_name else ""
    user = (
        "The C below failed to compile with `gcc -fsyntax-only`. Fix the "
        "errors and return ONLY the corrected C between ```c fences. Do "
        "not change anything else.\n\n"
        f"{head}\n\nErrors:\n```\n{compiler_errors}\n```\n\n"
        f"Code:\n```c\n{refined_code}\n```"
    )
    return sys_p, user


def verify_rename_prompt(
    decomp: str,
    *,
    suggested_name: str,
    callers: list[str] | None = None,
    callees: list[str] | None = None,
) -> tuple[str, str]:
    """Sidekick-style refutation pass over a proposed function name.

    The verifier is asked to *refute* the rename — it defaults to
    refuted=true unless the code provides positive evidence the name is
    semantically correct. This catches the common failure mode where
    the primary suggester emits a confident-but-wrong name from a single
    suggestive call inside an unrelated function.

    The reply must be a single line of strict JSON so we can parse it
    without prose-stripping heuristics on the hot path.
    """
    callers_s = ", ".join(callers) if callers else "(none)"
    callees_s = ", ".join(callees) if callees else "(none)"
    sys_p = (
        ANALYST_PERSONA + " You are a verifier, not a generator. Your "
        "job is to refute proposed function renames unless the code "
        "clearly supports them. Default to refuted=true when uncertain. "
        "False accepts corrupt overlays; false refusals merely keep "
        "the placeholder."
    )
    user = (
        "Given this code and proposed name, is the name semantically "
        "correct? Default to refuted=true if uncertain. Respond ONLY "
        'with JSON {"accepted": <bool>, "confidence": <0.0-1.0>, '
        '"reason": "<one short sentence>"}.\n\n'
        f"Proposed name: {suggested_name}\n"
        f"Callers: {callers_s}\n"
        f"Callees: {callees_s}\n\n"
        f"```c\n{decomp}\n```"
    )
    return sys_p, user


def batch_rename_prompt(
    decomp: str,
    *,
    current_name: str = "",
    callers: list[str] | None = None,
    callees: list[str] | None = None,
) -> tuple[str, str]:
    """Suggest a function name + confidence, grounded in callgraph context.

    Inspired by SymGen (NDSS 2025): generative function naming generalises
    far better than classification when out-of-distribution. We feed the
    callers and callees as additional context — empirically the most
    predictive features after the body itself.

    The model returns JSON: `{name, confidence}` so callers can threshold
    before auto-applying renames to the overlay.
    """
    callers_s = ", ".join(callers) if callers else "(none)"
    callees_s = ", ".join(callees) if callees else "(none)"
    sys_p = (
        ANALYST_PERSONA + " You will be asked to name many functions in "
        "batch. Be conservative — when uncertain, lower the confidence "
        "score and keep the placeholder. Hallucinations break overlays."
    )
    user = (
        "Suggest a snake_case name (max 40 chars) for this function. "
        "Return ONLY a single line of JSON: "
        '{"name": "<snake_case>", "confidence": <0.0-1.0>}.\n\n'
        f"Current name: {current_name or '(stripped)'}\n"
        f"Callers: {callers_s}\n"
        f"Callees: {callees_s}\n\n"
        f"```c\n{decomp}\n```"
    )
    return sys_p, user
