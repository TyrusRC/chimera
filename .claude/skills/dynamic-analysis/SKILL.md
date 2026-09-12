---
name: dynamic-analysis
description: Use when a target resists static analysis (a huge generated state machine, an obfuscated/flattened VM, hand-rolled crypto keyed on runtime state, an opaque validator) and running it — or emulating one routine / the whole image — would answer the question far cheaper. Covers using execution as an oracle, offline full-image emulation + CFG deflattening of obfuscated VMs, running Windows PEs on Linux under Wine safely, capturing GUI/MessageBox output headless, detecting & neutralizing anti-debug/anti-analysis checks, and when a dynamic oracle does NOT exist so you must extract statically.
---

# Dynamic analysis: execution as an oracle

Static reading is not always the cheapest path. When a validator is enormous,
generated, or state-dependent, **running it as an oracle** — feeding inputs and
observing a signal — often beats hand-tracing thousands of instructions. But
first prove an oracle exists; if it doesn't, don't thrash — extract statically.

## Decide: is there an oracle?

A usable oracle gives **partial-progress feedback** you can hill-climb on:
- a per-character/position "matched so far" counter (greedy solve: 16 chars ⇒
  ~16×alphabet runs, not alphabet¹⁶),
- persisted state that advances on a correct step (files, registry, **NTFS
  Alternate Data Streams**, a mmap),
- a branch/instruction/syscall count that rises as more input matches.

Test it cheaply before committing: run a few candidates, diff the observable.
**If every wrong input collapses to the same reset state (no partial signal),
there is no greedy oracle** — stop probing and extract the logic statically
(see "Generated state machines"). Verify this three ways before concluding it
(post-run state, seeding the state yourself, an execution counter) — don't
assume from one.

## Emulate an obfuscated routine offline (no Wine, deterministic)

For an obfuscated x86-64 PE — a control-flow-flattened / MBA / computed-goto VM
whose blocks end in `jmp rax` — you often don't need to run the whole program.
Two chimera primitives beat both hand-tracing and a fragile GUI run:

- **`recover_cfg` / `chimera deflatten`** — resolves the computed `jmp rax`
  edges (liveness-backtrack each block's footer, emulate it with the image
  mapped) and returns the real CFG + DOT. Use it to find the good-boy/bad-boy
  split and the gate that checks a value against a hardcoded constant.
- **`emulate_function full_image=true` / `chimera emulate --full-image`** — maps
  the WHOLE PE, stubs any call leaving the code sections (imports/Qt/syscalls
  no longer halt it), lazily maps faults, uses the MS-x64 ABI, and captures the
  printable strings the run writes. It runs the flattened routine to completion
  where the plain leaf-emulator (`emulate_function`) halts at the first `call`.

**Do not force a single branch to "success" in the emulator.** The VM dispatch
is keyed on the exact runtime state; a forced or fake value derails it into a
garbage path (millions of junk instructions, no flag). The clean route is to
recover the *input* (the passcode/code) by inverting the recovered hash, not to
fake the state. See the re-workflow "flattened VM" recipe.

**When the flag is a runtime-only GUI artifact:** a Qt6/GUI PE under Wine+Xvfb
(no WM/GPU) frequently won't paint its main window, and synthetic keystrokes are
ignored — so you can't drive the keypad to make it print the flag. Top-level
*dialogs* still render, but if you can't drive input, recover the **input**
instead (it's the real answer); the flag string is then whatever the app prints
for that input on a real display. This is the same class as a nondeterministic
runtime popup — don't burn hours on the GUI once the input is recovered.

## Running Windows PEs on Linux under Wine (safe, headless, scriptable)

Wine turns a Windows CTF/malware binary into a runnable oracle on Linux.
**`run_under_wine` (MCP) / `chimera run-under-wine` packages all of the below in
one call** (isolated prefix warmed up once, headless/Xvfb, memory-scan needle) —
reach for it first; the manual recipe here is for when you need to vary a step.
Keep it isolated and observable:

- **Isolated prefix, quiet, no network side effects:**
  `WINEPREFIX=<scratch>/wp WINEDEBUG=-all WINEDLLOVERRIDES="mscoree,mshtml=d"`.
  Use a scratch dir, never the project tree — the target may write files next
  to itself (that's often the point).
- **Console app, no GUI:** unset `DISPLAY` — console I/O goes to stdout, and
  decoy `MessageBox`/`ShellExecute` calls fail harmlessly for lack of a display.
- **32-bit PE (`file` says PE32, not PE32+):** this build's wine is unified
  WoW64 — do **not** set `WINEARCH=win32`. It needs the i386 runtime
  (`dpkg --add-architecture i386 && apt install wine32:i386`), then a **fresh**
  prefix so `wineboot --init` populates `syswow64`. A missing
  `syswow64\ntdll.dll` (error c0000135) means 32-bit support isn't installed.
- **GUI app / the answer is in a window or MessageBox:** run under a virtual
  display — `Xvfb :99 -screen 0 1280x1024x16 &` then `DISPLAY=:99`. You rarely
  need to *see* it: a blocking `MessageBox` keeps its text resident, so **scan
  the process memory** for the answer instead of screenshotting/OCR (search
  both ASCII and UTF-16LE — Win32 `...W` APIs use wide strings). Use `xdotool`
  to enumerate/dismiss dialogs (`key Return`/`Escape`) so a self-spawning chain
  keeps progressing; disable the crash popup so a crashing step doesn't halt it
  (`reg add "HKCU\Software\Wine\WineDbg" /v ShowCrashDialog /t REG_DWORD /d 0`).
- **Read/write the target's own state:** wine exposes NTFS ADS as `file:stream`
  siblings on disk — read/seed them directly to inspect or drive a state machine.
- **Parallelize the slow part:** wine startup is ~seconds/run. For a brute over
  an oracle, give each worker its **own copy** of the exe (own state/ADS) and
  run copies concurrently — don't serialize hundreds of launches.
- **Limits:** wine may not faithfully reproduce every metamorphic/anti-analysis
  path (a step that "spasms" on Windows can page-fault under wine). A
  genuinely nondeterministic runtime-only result may simply not reproduce — say
  so rather than grind.

Prefer **`emulate_function`** (chimera/Unicorn) over a full run when you only
need one leaf routine's output and it has no OS/GUI dependencies.

## Recovering a value computed at runtime (a derived/decrypted key)

When the answer is a value the program **builds at runtime** — an AES key derived
or decrypted behind obfuscation (MBA, a flattened function), never a literal in
the file — don't hand-solve the obfuscation. Read the value at the instant it's
live:

- **Break at the function that consumes it and dump a register.** `chimera
  bp-dump` / MCP `run_with_breakpoints` launches the target under ptrace, breaks
  at an address, and dumps registers + pointer-target memory. No sudo — because
  chimera *launches* the target, ptrace is allowed even under
  `kernel.yama.ptrace_scope=1` (that only blocks *attaching* to a non-child; a
  sibling gdb is blocked, this is not). e.g. break at a tiny-AES
  `AES_init_ctx_iv(ctx,key,iv)` and read 32 bytes at `[rdx]` (key) + 16 at `[r8]`
  (iv). **Ceiling:** breakpoints arm at the exec-stop, so the address must be
  mapped then — a native ELF's `.text` is; a **Windows PE the Wine loader maps
  later** is not, so bp-dump can't yet break inside a PE-under-Wine (a
  deferred-arm-on-module-load follow-up would close that).
- **Or scan memory for the key schedule.** `chimera aeskeys` / MCP
  `find_aes_keys` finds valid AES-128/192/256 key schedules in a file, a live
  PID's memory, or a hex blob — the schedule is self-checking, so the key falls
  out even when it's obfuscated in the binary. It also reports the 16 bytes after
  the schedule as a candidate IV (tiny-AES-c layout). The catch is timing: the
  schedule can be **transient** (a stack local, gone in ~ms) — freeze the process
  at the right point (block it in a hooked libc call, or SIGSTOP it) before you
  scan, or dump a core. If every wrong path collapses instantly, a periodic scan
  will miss it; prefer the breakpoint.

## Anti-analysis: detect it, then neutralize it

Before assuming a target "crashed" or "exits early," check whether it detected
the analysis environment. Grep the binary first (static scan is free):
`ptrace(`, `/proc/self/status`, `/proc/self/maps`, `rdtsc`, `signal(SIGTRAP`,
`fork(`, and on Windows `IsDebuggerPresent`, `NtQueryInformationProcess`,
`QueryPerformanceCounter`/`GetTickCount`, `CheckRemoteDebuggerPresent`.

Detection → neutralization on this Linux/Wine box:
- **`ptrace(PTRACE_TRACEME)` self-trace / a fork watchdog** — run the debugger as
  the *parent* (bp-dump launches the child, so scope=1 is fine), and
  `set follow-fork-mode child` + `set detach-on-fork off` to hold both processes.
- **`/proc/self/status` `TracerPid` != 0** — an `LD_PRELOAD` shim over `fopen`/
  `open`/`read` that rewrites the `TracerPid:` line to 0 (Wine reads the Linux
  `/proc`, so the shim goes on the ELF wine process).
- **Timing (`rdtsc`, `clock_gettime`, `QueryPerformanceCounter`)** used to detect
  single-stepping — don't single-step; run free to a breakpoint. If a threshold
  gates execution, LD_PRELOAD a fixed `clock_gettime`, or patch the compare.
  (`rdtsc` spin-loops are also just obfuscation stalls — emulate past them.)
- **`IsDebuggerPresent` / PEB `BeingDebugged` (+0x02) / `NtGlobalFlag` (PEB+0xBC
  == 0x70) / heap ForceFlags** under Wine — patch the check site, or hook the API
  to return 0; these are the classic Windows tells.
- **A launcher/env self-check** (won't run unless started a certain way) — see
  the re-workflow "anti-tamper / launcher checks" note (getenv-gated launch).
Neutralize the check, don't fight the symptom: an "early exit" is usually a
passed anti-debug test, not a real bug.

## Generated state machines (when you must go static)

A binary that is mostly one giant generated table/dispatch (huge function count,
a big array of code RVAs, `state`/`transition` labels) is a search problem, not
a reading problem — and even the author generated it, so there is a **uniform
per-state pattern** to script:

1. Find the state-handler dispatch (an array of RVAs, or a jump table). Its
   length is the state count. **Use `find_dispatch_tables` (MCP) / `chimera
   dispatch-tables`** — it recovers the array validated against executable
   sections (so it works even when the handlers aren't in `.pdata`); the biggest
   table is the one you want.
2. Disassemble one handler (`disassemble_many` bulk-does the table's targets;
   capstone if the built-in disassembler can't, e.g. an ILT binary — see
   re-workflow); read the transition idiom (typically `cmp <input>, <char>` /
   `je L`; at `L`, `mov <state_var>, <next_state>`). Bound each handler by its
   dispatch-restart jump, not a guessed size.
3. Build the edge list, then **`pathfind` (MCP) / `chimera pathfind`** for the
   accepting input — pass `exact_length` for the fixed-length-password shape.
4. Confirm dynamically: feed the recovered input to the real binary (for a
   Windows PE, **`run_under_wine` / `chimera run-under-wine`**).

**On-chain / embedded bytecode:** if the "algorithm" turns out to be EVM
smart-contract bytecode (deployed on a chain, or stashed as a hex const — a
"web3" wrapper is often just this), don't deploy to a testnet. **`evm_tour`
(MCP) / `chimera evm`** disassembles it, recovers the function selectors, and
*executes* a leaf `pure`/`view` function against calldata (bounded interpreter,
no node) so you can verify a formula by running it.

**Gotcha:** capstone prints small immediates as bare decimals (`2`, not `0x2`);
parse with `int(x, 16)` and don't require a `0x` prefix.

## When to reach for this vs. static

- Answer is a runtime artifact (a printed/boxed string, a decrypted file, a
  network beacon) → run it.
- Validator is huge/generated but each step is simple → extract statically,
  then confirm with one run.
- One leaf computes a value from fixed inputs → `emulate_function`.
- No partial oracle AND enormous logic AND running won't reveal it → say the
  cost honestly; don't fake a result.
