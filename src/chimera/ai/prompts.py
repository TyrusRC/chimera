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
