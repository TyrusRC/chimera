---
name: sast-bridge
description: Use after decompiling/extracting source from a binary to find vulnerabilities via SAST — the RE→SAST bridge. Covers mantis_audit (multi-engine with native C/C++ rules) + run_opengrep on decompiled output. Load when the question shifts from "how does it work" to "does it have security bugs."
---

# SAST bridge (decompiled source → vulnerability findings)

After chimera decompiles a binary (jadx for Android, ILSpy for .NET, r2ghidra
for native), the recovered source can be scanned for vulnerabilities. This skill
sets the right tool and pack for each source type.

## When to use

- After `analyze` on an APK → jadx produced Java/Kotlin source → scan it
- After `decompile` on a native function → r2ghidra produced C → scan it
- After `dotnet_extract` + ILSpy → C# source → scan it
- After `py_extract` / `py_unwrap` → Python source → scan it
- After `node_extract` / `js_deobf` → JavaScript source → scan it

## Tool selection

### mantis_audit (preferred — multi-engine, richer findings)

```
mantis_audit(path="<decompiled_tree>", decompiled=true)
```

mantis auto-detects the language from file extensions and picks the right rule
packs. For explicit control:

| Source type | Command |
|-------------|---------|
| Java/Kotlin (jadx) | `mantis_audit(path, mode="mobile")` |
| C/C++ (Ghidra/r2) | `mantis_audit(path, packs=["native"], language="c")` |
| C# (.NET/ILSpy) | `mantis_audit(path, mode="web")` |
| Python | `mantis_audit(path, mode="web")` |
| JavaScript | `mantis_audit(path, mode="web")` |
| Malware sample | `mantis_audit(path, packs=["native", "secrets"], language="c")` |

The `native` pack (23 rules) covers:
- Buffer overflows, format strings, command injection, UAF, integer overflow
- Malware patterns: process injection, shellcode callbacks, PEB walk, anti-debug,
  registry persistence, keylogging, suspicious network — with MITRE ATT&CK IDs

Additional params:
- `language="c"` — skip extension-based detection, tell mantis it's C directly
- `timeout=120` — cap the scanner run (useful for large decompiled trees)
- `engines="none"` — OpenGrep rules only, skip bandit/gosec/trivy layer
- `llm=true` — add LLM-based triage (needs a configured provider)

### run_opengrep (lightweight — chimera's built-in, no mantis needed)

```
run_opengrep(rules="auto")
```

Runs OpenGrep on jadx output from the most recent `analyze` call. Lighter than
mantis (one engine, auto-detected rules), but enough for a quick check.

### vuln_scan (binary-level — no source needed)

```
vuln_scan()
```

Decompile-based heuristic pattern matching on the loaded binary's functions.
Catches gets/printf(var)/strcpy without needing a full decompile tree. Use as
a fast first pass before the heavier SAST run.

## Workflow

1. **Analyze the binary.** `analyze(path=...)` — this produces the decompiled
   source that SAST will scan.
2. **Quick binary-level scan.** `vuln_scan()` — fast heuristic pass on
   decompiled functions. Catches the obvious bugs.
3. **Full SAST scan.** `mantis_audit(path=<jadx_or_ghidra_output>, decompiled=true)`
   — multi-engine scan with proper rules. This is the thorough pass.
4. **Triage findings.** Review mantis findings — each has rule_id, severity,
   confidence, CWE, and the code slice. Focus on ERROR/HIGH first.
5. **Confirm exploitability.** For each confirmed finding, switch to the
   `exploit-workflow` skill to build a PoC.

## Integration with centurion

For mobile apps, centurion provides additional MASTG-specific checks:

```
centurion_tools()  # see what's available
```

centurion wraps apkid, apkleaks, and the MASVS verification framework.
Use it alongside mantis for a comprehensive mobile security assessment.

## Anti-patterns

- Running mantis on the RAW binary (it's a SAST tool, not a binary scanner).
  Always decompile first, then point mantis at the source tree.
- Using `mode="deep"` on a 10K-file jadx tree — use `mode="quick"` or
  specific `packs` to scope the scan.
- Ignoring the `decompiled=true` flag — without it, mantis may misdetect the
  stack (no build files in a decompiled tree).
