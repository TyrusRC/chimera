---
name: sast-workflow
description: Use after decompiling/extracting source from a binary to find vulnerabilities with SAST. Covers mantis_audit + run_opengrep on decompiled output — the RE→SAST bridge. Load this after analyze/decompile when the question is "does this code have security bugs" rather than "how does it work."
---

# SAST on decompiled code (the RE→security bridge)

The goal: once chimera has recovered source (jadx, ILSpy, r2ghidra, pyextract,
node_extract, tauri_extract, js_deobf), scan it for vulnerabilities — not by
hand-reading, but with SAST rules. Two tools, cheap→full.

## When to load this skill

- After `analyze` produces jadx/ILSpy output on a mobile app or .NET binary
- After `py_extract` / `node_extract` / `tauri_extract` / `js_deobf` recovers source
- After `decompile` / `get_function` outputs C code from a native binary
- When the question shifts from "what is this" to "is it vulnerable"

## The two SAST tools

### `run_opengrep` (fast, narrow)
OpenGrep SAST rules on jadx/apktool decompiled output. Requires a prior
`analyze` call that ran jadx. Best for quick Java/Kotlin mobile checks.
```
run_opengrep(rules="auto")     # auto-detects language from jadx output
run_opengrep(rules="p/java")   # explicit Java rules
```

### `mantis_audit` (full, multi-engine)
The heavy tool. Runs OpenGrep **plus** a multi-engine layer (bandit, gosec,
njsscan, eslint-security, checkov, trivy/grype) and deduplicates. Covers
more languages and deeper checks.

**For decompiled native code (C from r2/Ghidra):**
```
mantis_audit(path="/path/to/decompiled/", packs=["native"], language="c")
```
The `native` pack has 23 rules covering BOF (gets/strcpy/sprintf), format
strings, command injection, UAF, integer overflow, anti-debug patterns, and
MITRE ATT&CK–mapped malware indicators.

**For mobile (jadx output):**
```
mantis_audit(path="/path/to/jadx/sources/", mode="mobile")
```

**For web (extracted JS/HTML):**
```
mantis_audit(path="/path/to/extracted/", mode="web")
```

**For secrets in any code:**
```
mantis_audit(path="/path/to/sources/", mode="secrets")
```

**Offline mode (skip trivy/grype network SCA):**
```
mantis_audit(path="...", engines_offline=True)
```

## The flow

1. **Recover source.** `analyze` (mobile → jadx), `py_extract` (PyInstaller),
   `node_extract` (Node binary), `decompile` (native → C). The output dir is
   your SAST target.
2. **Quick scan.** `run_opengrep(rules="auto")` for a fast pass — takes seconds,
   catches the obvious. Review findings.
3. **Full audit.** `mantis_audit(path=..., decompiled=True)` for the full
   multi-engine run. `decompiled=True` (the default) tells mantis to detect
   the language from file extensions, not build files — the usual chimera case.
4. **Triage.** Review findings by severity. Cross-reference with `get_function`
   decompilation to verify true positives. Use `add_note` to record confirmed
   vulns.

## Anti-patterns

- Running SAST before recovering source (mantis needs files, not a binary).
- Using `mode="deep"` on huge jadx output (slow; start with `mode="quick"`).
- Trusting SAST findings without verifying the decompiled code (decompiler
  artifacts cause false positives — always `get_function` the flagged code).
- Scanning the Ghidra/r2 runtime itself instead of the decompiled output dir.
