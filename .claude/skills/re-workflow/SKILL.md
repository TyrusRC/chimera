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
   `gpu-acceleration` skill for a crack. When the logic is huge, generated, or
   keyed on runtime state, **consider the `dynamic-analysis` skill** — running
   the target as an oracle (Wine for Windows PEs on Linux, or `emulate_function`
   for one routine) can beat hand-tracing thousands of instructions; if no
   oracle exists, it also covers extracting a generated state machine statically.
   **Reach for a solving primitive before hand-scripting** (these exist so you
   don't re-roll them each time): `find_dispatch_tables` recovers a state/jump
   table (the biggest one is usually the state count) even on an ILT binary;
   `disassemble_many` bulk-disassembles its targets; `pathfind` BFS-searches a
   recovered FSM edge list for the accepting input (`exact_length` = the N-char
   password shape); `run_under_wine` is the one-call Wine oracle; `evm_tour`
   disassembles/executes on-chain EVM bytecode (a `pure` function) with no node;
   `bp-dump`/`run_with_breakpoints` reads a runtime-computed value (a derived key)
   at a breakpoint with no sudo; `aeskeys`/`find_aes_keys` recovers an AES key
   from a memory dump or live process. See the `dynamic-analysis` skill for the
   runtime-key-recovery playbook.
   Persist findings with the write-back tools (`rename_function`, `set_comment`,
   `add_note`, `batch_annotate`) so the reasoning survives compaction and the
   next session reads it back.

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

## Gotchas that mislead recon
- **A function count ≈ the import count on a native PE64 is a lie.** A
  `/INCREMENTAL`-linked MSVC binary routes calls through an Incremental Link
  Table of `jmp` thunks that defeats a disassembler's call-graph walk (it
  reports ~112 when there are thousands). Chimera cross-checks `.pdata`'s
  RUNTIME_FUNCTION table and backfills; `analyze` warns when this happens.
  Resolve each `call`/`jmp` through its ILT thunk before trusting an edge, and
  a capstone disasm fallback (`[disasm]` extra) reads functions r2 can't.
- **`native` in the framework line reads as C/C++ but may not be** — chimera
  now fingerprints the VB6/twinBASIC family; watch for other runtimes hiding
  behind `native` (Delphi, Go, Rust).
- **A section at ~random entropy over a large fraction of the file** is the
  likely encrypted/compressed payload — chimera surfaces it in the summary.

## Anti-patterns
- Running `analyze` (slow, Ghidra-heavy) before cheap detection has told you
  it's even the right instrument — a source-provided or bytecode target may
  need no disassembly at all (see the `python-bytecode` skill).
- Drilling before the mindset call. Depth without a named path burns tokens.
- Pulling full strings/disassembly into main context instead of a subagent.
- Hand-tracing a huge generated validator when an oracle would answer it, OR
  grinding a dynamic oracle that doesn't exist — the `dynamic-analysis` skill
  is the decision guide.
