---
name: desktop-re
description: Use when the target is a desktop/native executable — a Windows PE (.exe/.dll/.sys) or a Linux/Unix ELF (.so/binary) — for a crackme, keygen, CLI tool, licensed app, or malware. Sets the native static→dynamic flow over chimera's tools (analyze/decompile/disasm/dispatch/deflatten/emulate/symexec/wine/bp-dump) and the PE-vs-ELF specifics that trip people up. Load after re-workflow's recon for a native target; use mobile-re for APK/IPA, python-bytecode for frozen Python.
---

# Desktop / native RE (Windows PE + Linux ELF)

For a compiled native binary the answer is a specific routine — a license check,
a decode, a config — reached fast by triaging format + finding the logic, not by
reading every function. Follow `re-workflow`'s recon+mindset first; this adds the
native-specific moves.

## Recon (format decides the toolchain)
`analyze` → `detect_framework` / `detect_protections` → `get_info`. Establish:
arch (x86/x64/arm64), compiler/runtime (MSVC / MinGW / GCC/Clang / Go / Rust /
VB6-twinBASIC / .NET), packer/protector (UPX, VMProtect, Themida, ConfuserEx),
and entropy anomalies (a big high-entropy section = encrypted/compressed payload
— unpack before reading). `get_strings` (paged) then `deobfuscate_strings`
(FLOSS) for hidden ones; `detect_capabilities` (capa) for a malware "what can it
do" map.

## Unpack / deobfuscate before reading
- Packed → `unpack` (UPX etc.); VMProtect → `vmp-devirt`; Rust → `rust-decompile`
  (Oxidizer). Go/Rust strip symbols — recover them (Go pclntab, Rust panic
  strings) before trusting the call graph.
- Control-flow-flattened / MBA / computed-`jmp rax` VM → `recover_cfg`
  (`chimera deflatten`) + `emulate_function full_image=true`; see the re-workflow
  flattened-VM recipe. `find_dispatch_tables` locates a generated FSM's state table.

## Find the logic, then read it
- `find_dispatch_tables` / `get_callgraph` / xrefs to zero in; `decompile`
  (r2ghidra `pdg` → `pdc`) or `get_function` for C; `get_disassembly` (paged) for
  the exact instructions. `pathfind` walks a recovered FSM to the accepting input.
- Leaf hash/decrypt/checksum → `emulate_function` (or `full_image` for an
  obfuscated one) to get its output without running the program.
- Unknown input to a check (crackme/keygen/serial) → `symexec` (angr): declare
  symbolic stdin/argv, `find` the win address / `find_stdout` the success string,
  `avoid` the failure — let the solver hand back the input. Don't hand-invert
  first. For a real crack/keyspace brute, `detect_gpu` + the `gpu-acceleration`
  skill (invert, don't brute, when you can).

## PE-specific (Windows)
- **Function count ≈ import count on a /INCREMENTAL MSVC PE64 is a lie** — the ILT
  of `jmp` thunks defeats the call-graph walk; chimera backfills from `.pdata`
  (analyze warns). Resolve calls through their ILT thunk before trusting an edge.
- IAT/imports = capability surface; delay-load + `GetProcAddress` hide it — check
  strings/`.rdata`. TLS callbacks + `.CRT`/ctors run before `main` (a common
  anti-analysis / init spot). Read `.rsrc` (icons/manifests/embedded payloads).
- `native` may hide VB6/twinBASIC/Delphi/Go/Rust — chimera fingerprints these.
  `.NET` PE → the managed lane (`dotnet_trace`, IL tooling), not raw x86.

## ELF-specific (Linux)
- PLT/GOT indirection: resolve `call <fn>@plt` → the real import. `.init_array`/
  constructors run before `main`. Static vs dynamic linking changes everything
  (a static musl/glibc binary inlines libc — FLIRT/signatures help label it).
- Stripped is normal — lean on `.dynsym`, string/xref anchors, and capa; symbol
  recovery for Go/Rust as above.

## Dynamic (when static stalls)
Run it as an oracle — `run_under_wine` for a PE on Linux, `run_sandboxed` for an
ELF (net off) — see the `dynamic-analysis` skill (execution-as-oracle, anti-debug
detect/neutralize, full-image emulation). Grab a runtime-built key with `bp-dump`
/ `find_aes_keys`. If it's malware, switch to the `malware-triage` skill.

## Anti-patterns
- Reading disassembly before unpacking, or before the mindset call names the one
  routine that matters. Hand-tracing an obfuscated VM instead of `recover_cfg` +
  `emulate_function`. Brute-forcing a check `symexec` would invert. Trusting a
  call graph on an ILT-obscured PE64 or PLT-indirected ELF without resolving thunks.
