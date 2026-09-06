---
name: re-workflow
description: Use when reverse-engineering or triaging a binary/CTF challenge/crackme/malware sample with chimera — sets the recon-first mindset, the cheap→expensive MCP call order, when to offload to a subagent, and how to log tool gaps. Load this before touching a new target.
---

# Chimera RE Workflow (mindset first, token-aware)

The goal is to reach the answer with the fewest expensive calls and the least
context bloat. **Breadth before depth. Name the path before drilling.**

## The loop

1. **Recon (breadth-first, cheap).** Establish what the target *is* before
   analyzing how it works. Order, cheapest first:
   - `status` → `detect_framework` / `detect_protections` → `get_info`
   - `get_strings` (paged: `offset`/`limit` — never pull all at once)
   - only then `analyze` (the expensive full pass), then `get_functions`
   - If recon means reading large dumps (full strings, disassembly, many
     files), **spawn the `re-recon` subagent** so that output never lands in
     your context — you get back a triage summary, not the raw bytes.

2. **Mindset call (before any deep work).** State out loud, in one short block:
   - the target's class and the **single most likely path** to the answer
   - the **dead-ends** you will NOT pursue (and why) — this is what saves the
     most time
   - what would falsify the chosen path
   If a cheaper tool already answers the question (source present? strings
   leak the flag? a constant is right there?), take it and stop.

3. **Depth (one path, targeted).** Drill the chosen path only:
   `get_function` / `get_disassembly` (paged) / `emulate_function` for a leaf
   routine / `dotnet_trace` for VM'd .NET / `detect_gpu` + the
   `gpu-acceleration` skill for a crack. Persist findings with the write-back
   tools (`rename_function`, `set_comment`, `add_note`, `batch_annotate`) so
   the reasoning survives compaction and the next session reads it back.

4. **Log the gap.** Whenever you step outside chimera (stock `ast`/`dis`, a
   hand-rolled decryptor, an external tool), note it — that's a tool gap worth
   fixing. In a benchmark, hand it to `benchmark-supervisor`.

## Operating rules

- **Copilot with the user.** Surface recon/intel and your mindset call to the
  user and invite a course-correction *before* a long drill, not after.
- **On a small model (Sonnet/Haiku), consult Opus as advisor** for the mindset
  call and dead-end pruning before committing to a path — cheap insurance
  against a wasted deep dive.
- **No-API flow.** Everything routes through chimera's MCP tools + CLI; never
  assume a hosted API. `detect_gpu`, `emulate_function`, `pyextract` etc. all
  run locally.
- **Context hygiene = token savings.** Page every list. Offload heavy reads to
  a subagent. Don't re-read a file you just wrote. Keep only conclusions.

## Anti-patterns
- Running `analyze` (slow, Ghidra-heavy) before cheap detection has told you
  it's even the right instrument — a source-provided or bytecode target may
  need no disassembly at all (see the `python-bytecode` skill).
- Drilling before the mindset call. Depth without a named path burns tokens.
- Pulling full strings/disassembly into main context instead of a subagent.
