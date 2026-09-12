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
   table (the biggest one is usually the state count) even on an ILT binary —
   and when it finds NO strong table, the target is likely a **control-flow-
   flattened / MBA / computed-goto VM** (every block ends in `jmp rax`), so reach
   for `recover_cfg` (MCP) / `chimera deflatten` — it liveness-backtracks each
   block's footer expression and emulates it (whole image mapped) to resolve the
   computed successors, returning the real edges + a DOT (this is the Ghidra-
   script deflattening from Flare-On-style write-ups, in chimera, no Ghidra);
   `emulate_function full_image=true` / `chimera emulate --full-image` runs an
   obfuscated routine end-to-end (maps the whole PE, stubs import/Qt/syscall
   calls, lazily maps faults, MS-x64 ABI, captures printable writes) when the
   plain leaf-emulator halts at the first `call`; `disassemble_many`
   bulk-disassembles its targets; `pathfind` BFS-searches a
   recovered FSM edge list for the accepting input (`exact_length` = the N-char
   password shape); `run_under_wine` is the one-call Wine oracle; `evm_tour`
   disassembles/executes on-chain EVM bytecode (a `pure` function) with no node;
   `bp-dump`/`run_with_breakpoints` reads a runtime-computed value (a derived key)
   at a breakpoint with no sudo; `aeskeys`/`find_aes_keys` recovers an AES key
   from a memory dump or live process. See the `dynamic-analysis` skill for the
   runtime-key-recovery playbook. **To actually EXECUTE an untrusted target**
   (crackme/malware/CTF/Wine PE) do it confined — `chimera sandbox-run` or the
   `sandbox-runner` agent; see the `sandbox` skill (network off by default).
   Persist findings with the write-back tools (`rename_function`, `set_comment`,
   `add_note`, `batch_annotate`) so the reasoning survives compaction and the
   next session reads it back.

4. **Log the gap, then fill it.** Whenever you step outside chimera (stock
   `ast`/`dis`, a hand-rolled decryptor, an external tool), that's a capability
   gap — the goal is to build the missing primitive so it's never re-rolled. To
   rank which gaps to fill first, hand the solve to the `benchmark-supervisor`
   (gap-auditor) agent for a prioritized fix list.

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

## Recipe: control-flow-flattened / MBA / computed-goto VM

When a function is a wall of pointer-encrypted calls + MBA arithmetic ending in
`jmp rax` (Flare-On-style obfuscation), do NOT hand-trace it and do NOT try to
force a single branch in an emulator (the dispatch is keyed on the exact state,
so a forced/foreign value derails into garbage). Instead:

1. `recover_cfg(path, entry)` → the real CFG. Zoom out: one node usually splits
   the graph into a `QMessageBox::warning`/bad-boy half and an
   `information`/good-boy half. That split node's condition is the check.
2. Find the gate: the block before the split compares a computed value to a
   hardcoded constant (`movabs rcx, <target>; sub; sete`). That constant is the
   target hash/checksum — recover it (it's the same value whether you read it
   statically at the gate or via the emulator).
3. Recover the per-element update that builds the checked value (the keypress /
   per-byte hash). `emulate_function full_image=true` runs it end-to-end;
   diff two runs with different inputs to isolate the input-dependent ops, or
   pull the multiplier/mod constants straight from the disasm. Reduce it to a
   small Python model.
4. Invert offline (branch-and-bound / modular inverse / BFS) to get the input.
   The **flag is often decrypted at runtime keyed on that input** — so the input
   (passcode/code) is the deliverable; enter it in the real app for the flag
   string, or emulate the decrypt with the input if it's self-contained.

**Different shape — a classic bytecode interpreter** (a dispatch LOOP reading
opcodes from a bytecode blob, not per-block computed jumps): find the loop by
its fetch/decode/handler signature (`op = code[pc++]` → `switch`/`jmp
[table+op*8]`/threaded `goto *handlers[op]`); locate the VM context struct (pc,
stack, registers, the code pointer); enumerate every handler and infer each
operand's width from how many times it does `pc++`; build an `{opcode → mnemonic,
operands, semantics}` ISA dictionary and write a small disassembler over the
blob, then re-host it in Python to solve. `find_dispatch_tables` locates the
handler table (biggest = opcode count); `dotnet_trace` covers a VM'd .NET
method. For VMProtect/Themida, cluster 20–30 handler samples by operand pattern.

## Anti-tamper / launcher checks (do this before fighting a crash)
A GUI target may refuse to run unless launched a specific way — e.g. it calls
`getenv("SOME_VAR")` at startup and `exit(1)`+MessageBox if unset (the var is
set by its `run.bat`). Find the check (grep the adjacent strings → the `getenv`
+ `cmp rax,0` site), then satisfy it: under Wine, a Unix export is NOT forwarded
to the CRT — set it in `HKCU\Environment` (`wine reg add`) or a `cmd /c set …&&`
launch. Qt6 under Wine+Xvfb (no WM/GPU) often paints the main window BLACK, but
top-level *dialogs* (incl. the success/flag MessageBox) still render — so a
runtime flag can be read from the dialog if you can drive input; if you can't
(keypad won't render, input is synthetic-ignored), recover the input instead
(see the VM recipe) rather than fighting the GUI.

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
- **Cross-platform mobile frameworks have dedicated tools** — don't try to read
  Dart AOT or Hermes bytecode as plain native/JS. **Flutter**: `chimera
  flutter-extract` (static B(l)utter — Dart classes/methods) and `chimera
  flutter-patch` (reFlutter — repackage for traffic MITM, since Flutter ignores
  the system proxy + bundles its own CA, or dump Dart code offsets). **React
  Native**: `analyze` auto-detects the bundle and runs `hermes-decompile`
  (Hermes bytecode) or webcrack (plain-JSC minified bundle) + source-map
  recovery. **Others**: `rust-decompile`, `vmp-devirt` (VMProtect).
- **R8/ProGuard-obfuscated Android**: `a.b.c` class names aren't a dead end —
  Kotlin `@Metadata`/`@DebugMetadata` annotations survive R8 and carry the
  original fully-qualified names, so an obfuscated→real map is recoverable
  (near-100% on `*Repository`/`*ViewModel`/`*UseCase`). Fingerprint the HTTP
  stack (Retrofit/OkHttp/Ktor/Apollo) and DI (Koin/Hilt) early, then trace
  UI → ViewModel → repository → network rather than grepping for endpoints.

## Anti-patterns
- Running `analyze` (slow, Ghidra-heavy) before cheap detection has told you
  it's even the right instrument — a source-provided or bytecode target may
  need no disassembly at all (see the `python-bytecode` skill).
- Drilling before the mindset call. Depth without a named path burns tokens.
- Pulling full strings/disassembly into main context instead of a subagent.
- Hand-tracing a huge generated validator when an oracle would answer it, OR
  grinding a dynamic oracle that doesn't exist — the `dynamic-analysis` skill
  is the decision guide.
- **For a network+RE target (binary + pcap): decrypt the CAPTURE statically
  first — don't chase a runtime key.** The intended solve is usually to reverse
  the protocol/key derivation from the binary and decrypt the recorded traffic
  offline. The traffic often *leaks the very inputs the key depends on*: a token
  or header in the capture can be a reversible encoding of the environment
  (time / user / hostname) that the key is derived from — recover those by
  inverting it, no execution needed. Trying to run the sample to dump the key
  frequently FAILS (it depends on time/user/host/peer that differ on replay, so
  it exits or crashes before the crypto) and burns huge effort. Reach for the
  dynamic key-grab (Wine + `bp-dump`) only after confirming the key genuinely
  can't be derived from the binary + capture.
