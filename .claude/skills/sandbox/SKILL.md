---
name: sandbox
description: Use when you need to RUN an untrusted or unknown program (a crackme, a malware sample, a CTF binary, a Windows PE under Wine) — safely and with full control. Covers the fast no-root bubblewrap sandbox, when to reach for a QEMU VM instead, the host config (ptrace_scope) that dynamic key-extraction needs, and how the RE tools compose inside the sandbox.
---

# Running programs safely and freely (sandbox)

Dynamic analysis means executing code you don't trust. Do it confined, so a
sample can't beacon out, pull a payload, or scribble on the host — while you keep
full control (ptrace, breakpoints, memory reads) to observe it.

## Pick the confinement

- **bubblewrap (default, fast, no root, no daemon)** — `chimera sandbox-run`
  (MCP `run_sandboxed`). Isolated PID/mount/IPC/**net** namespaces, network OFF
  unless `--net`, throwaway tmpfs for `/tmp` and `$HOME`, host FS read-only except
  explicit `--ro`/`--rw` binds. Runs on the host kernel, so it's instant and
  **ptrace / `bp-dump` still work inside**. This is the right tool for a Linux
  ELF or a Wine-hosted PE (`--wine`). It is NOT a security boundary against a
  kernel exploit (shared kernel) — it's isolation against ordinary sample
  behaviour (exfil, file writes, persistence).
- **QEMU VM (full isolation / a real Windows guest / root-needing configs)** —
  `qemu-system-x86_64` is present but there's no `/dev/kvm` here, so it's TCG
  software emulation (correct, just slow). Reach for it when: you need a
  different kernel or a kernel knob you can't set on the host, you want a
  disposable throwaway that a kernel-aware sample can't escape, or you need a
  genuine Windows environment (not Wine). Build a small Linux guest image, install
  the tools (wine, gdb, chimera), snapshot it, and drive it over SSH; revert the
  snapshot between samples. (A prebuilt image isn't shipped — provision once.)

## Host config the dynamic tools need (one-time, needs sudo)

- **`kernel.yama.ptrace_scope`** gates tracing. At `1` (Debian/Kali default) you
  can ptrace a child you *launched* but NOT attach to a sibling, and you CANNOT
  read `/proc/<pid>/mem` of a process Wine **reparented** (Wine daemonizes the
  real PE process out of your tree). So no-sudo `bp-dump` reaches a native ELF
  child but not a Wine PE. For gdb-attach or a memory scan of a Wine PE, set it
  once: `sudo sysctl kernel.yama.ptrace_scope=0`. Then attach to the
  image-hosting pid (find it: the pid whose `/proc/<pid>/maps` shows the `.exe`
  backing `0x140000000` — Wine honours a fixed ImageBase when ASLR doesn't
  relocate) and break at the function you want.
- **Unprivileged user namespaces** must be enabled for bubblewrap
  (`kernel.unprivileged_userns_clone=1`, or the kernel default).

## Driving it freely (persistent workspace)

For step-by-step control — not one-shot run-and-capture — pass a **`--workspace
<dir>`** (MCP `workspace`). That dir is bound rw as `$HOME` and is the working
dir, so everything persists across calls: files the target drops, a Wine prefix
(`<dir>/.wine`, so `wineboot` runs once), unpacked payloads, notes. Then just
issue command after command against the same workspace and build up state:

```
chimera sandbox-run --workspace /tmp/job -- ./target --dump-config   # step 1
chimera sandbox-run --workspace /tmp/job -- ls -la                   # inspect drops
chimera sandbox-run --workspace /tmp/job -- gdb -p <pid> ...         # drive it
chimera sandbox-run --workspace /tmp/job --wine -- sample.exe        # Wine, same prefix
```

Each call is a fresh namespace over the same persistent workspace, so you keep
full control while the confinement (network off, host RO) still holds. Add
`--net` only for the calls that truly need it. Inspect what the target did by
reading the workspace dir directly from the host between calls.

## Composing the RE tools inside the sandbox

- Run the target isolated: `chimera sandbox-run --wine -- target.exe` (net off).
- Read a runtime-computed value at a breakpoint: `chimera bp-dump` — for an ASLR
  target use a **signature+delta** breakpoint (find a known constant, e.g. an AES
  S-box, break at found+delta). For a Wine PE that loads at its ImageBase, a
  fixed `--addr` works.
- Recover an AES key from a dump or a live/frozen pid: `chimera aeskeys`.
- Feed a dead C2 by replaying the captured server responses from a mock HTTP
  server + an `LD_PRELOAD` `getaddrinfo` shim that points the C2 domain at your
  mock (Wine uses the Linux resolver, not the Windows hosts file); pairs with
  the `dynamic-analysis` skill.

## Gotchas
- `$HOME` is a throwaway tmpfs — a target (or interpreter/venv) **under `$HOME`
  is hidden** unless you `--rw`/`--ro` bind it back (binds overlay the tmpfs).
- Wine in a fresh prefix runs `wineboot` on first use (tens of seconds); reuse a
  prefix to avoid paying it each run.
- No network by default is the point — add `--net` only when the analysis needs
  it, and prefer pointing it at a mock rather than the real internet.
