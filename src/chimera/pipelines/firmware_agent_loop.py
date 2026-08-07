"""FirmAgent-pattern hybrid LLM + fuzzer loop for firmware bug-hunting.

FirmAgent (USENIX'24, Liu et al.) drives a fuzzer with LLM-proposed sinks
and feeds crash/coverage telemetry back so the model can refine its next
proposals. We don't ship a fuzzer wired in, so this module structures the
loop as a series of callable hooks the caller can replace. The default
hooks are no-ops — running with them gives a structurally valid (empty)
result that proves the wiring is correct.

Shape::

    targets = [{"address": "0x10c0", "context": "<decompiled code>"}, ...]
    result  = run_firmware_agent_loop(targets, llm_client, max_rounds=3)
    # result[i] = {"address", "rounds": [{"sinks": [...], "findings": [...]}]}

Keep this file ergonomically small — the value here is the loop control,
not domain-specific bug heuristics that would lock us into one fuzzer.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


# Hook signatures — callers can replace either with project-specific impls.
SinkProposer = Callable[[Any, dict, list[dict]], list[dict]]
"""(llm_client, target, prior_findings) -> [{"description", "address"?}, ...]"""

Fuzzer = Callable[[dict, list[dict]], list[dict]]
"""(target, sinks) -> [{"sink_index", "outcome", "evidence"?}, ...]"""


def _default_propose_sinks(
    llm_client: Any, target: dict, prior_findings: list[dict],
) -> list[dict]:
    """Ask the LLM for candidate sinks at `target.address`.

    Best-effort: works with any client matching `AIClient.complete(system,
    user) -> str`. Returns [] when the client doesn't conform — the loop
    continues with an empty round rather than crashing.
    """
    if llm_client is None or not hasattr(llm_client, "complete"):
        return []
    system = (
        "You are a firmware vulnerability researcher. Identify memory-safety "
        "and command-injection sinks in decompiled code worth fuzzing."
    )
    user = (
        f"Given this function at {target.get('address', '?')}, list up to 5 "
        "likely sinks (memcpy, strcpy, system, sprintf, …) you would fuzz. "
        "Reply as JSON list of {description, address?}.\n\n"
        f"Prior findings: {prior_findings}\n\n"
        f"Code:\n{target.get('context', '')}\n"
    )
    try:
        raw = llm_client.complete(system, user)
    except Exception as exc:  # noqa: BLE001
        logger.warning("LLM sink-proposal call failed: %s", exc)
        return []
    # We deliberately don't parse JSON here — keep the hook honest about
    # what it returns. Callers that want structured sinks should plug in
    # their own proposer that does the parsing.
    return [{"description": str(raw)[:512]}] if raw else []


def _default_fuzz(_target: dict, _sinks: list[dict]) -> list[dict]:
    """No-op fuzzer placeholder. Returns [] so the loop terminates cleanly."""
    return []


def run_firmware_agent_loop(
    targets: list[dict],
    llm_client: Any,
    *,
    max_rounds: int = 3,
    propose_sinks: Optional[SinkProposer] = None,
    fuzz: Optional[Fuzzer] = None,
) -> list[dict]:
    """Drive the propose → fuzz → feedback loop for each target.

    The loop terminates early when a round proposes zero sinks (nothing
    new to try) so callers don't pay for empty rounds. Findings from
    prior rounds are passed back to the proposer so it can avoid
    re-suggesting already-checked sinks.
    """
    if max_rounds < 1:
        raise ValueError("max_rounds must be >= 1")
    propose = propose_sinks or _default_propose_sinks
    fuzzer = fuzz or _default_fuzz

    results: list[dict] = []
    for target in targets:
        rounds: list[dict] = []
        prior: list[dict] = []
        for _ in range(max_rounds):
            sinks = propose(llm_client, target, prior)
            if not sinks:
                break
            findings = fuzzer(target, sinks)
            rounds.append({"sinks": sinks, "findings": findings})
            prior.extend(findings)
        results.append({
            "address": target.get("address", ""),
            "rounds": rounds,
        })
    return results
