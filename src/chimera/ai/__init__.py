"""LLM-backed analyst helpers — function explain, name suggestion, comments.

Chimera does not depend on the `anthropic` SDK; the client uses urllib so it
works on any wheel install. Configure with the `ANTHROPIC_API_KEY` env var;
override the model with `CHIMERA_AI_MODEL` (default: claude-sonnet-4-6) and
the endpoint with `ANTHROPIC_BASE_URL` (default: https://api.anthropic.com).

The AI surface is fail-soft: if no key is set, calls raise `AINotConfigured`
which the API maps to HTTP 503 with a clear message. Analysts who don't
want LLM features can simply not set the key.
"""

from chimera.ai.client import (
    AIClient,
    AINotConfigured,
    AIError,
    default_client,
)
from chimera.ai.parsing import (
    parse_rename_json,
    strip_fence,
)
from chimera.ai.prompts import (
    explain_prompt,
    rename_prompt,
    comment_prompt,
    refine_decomp_prompt,
    batch_rename_prompt,
    verify_rename_prompt,
)
from chimera.ai.verify import (
    VerifyResult,
    verify_rename,
)

__all__ = [
    "AIClient",
    "AINotConfigured",
    "AIError",
    "default_client",
    "explain_prompt",
    "rename_prompt",
    "comment_prompt",
    "refine_decomp_prompt",
    "batch_rename_prompt",
    "verify_rename_prompt",
    "VerifyResult",
    "verify_rename",
    "parse_rename_json",
    "strip_fence",
]
