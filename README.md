# Chimera

> Reverse engineering platform for desktop and mobile binaries. Many backends, one beast.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB.svg?logo=python&logoColor=white)](pyproject.toml)
[![Platform](https://img.shields.io/badge/platform-PE%20%7C%20ELF%20%7C%20Mach--O%20%7C%20.NET%20%7C%20Android%20%7C%20iOS-success.svg)](#features)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED.svg?logo=docker&logoColor=white)](Dockerfile)
[![MCP](https://img.shields.io/badge/MCP-compatible-5A4FCF.svg)](src/chimera/mcp_server.py)
[![Status](https://img.shields.io/badge/status-alpha-orange.svg)](#status)

Chimera is a unified wrapper around Ghidra, Radare2, jadx, Frida, capa,
YARA and a growing set of platform-specific tools. It analyzes Windows
PE / .NET assemblies, Linux ELF, macOS Mach-O, Android APKs and iOS
IPAs through one CLI, one project store and one HTTP API — no LLM
required — and exposes an optional MCP server so Claude or any
compatible model can drive the pipeline.

The static workflow (triage → decompile → annotate → patch → export)
runs headless out of the same Docker image as the mobile pipeline. The
desktop side adds: a FLIRT-equivalent library-function matcher, an r2 /
Ghidra side-by-side decompiler with substitution-style post-processing,
persistent renames / comments / type signatures, byte-level patching
with anti-debug recipes, a UPX auto-unpacker, packer detection
(YARA + section-name + entropy), and a gdb symbol bridge.

---

## Features

### Cross-platform binary analysis
- **Six formats, one pipeline** — Windows PE / PE32+ / .NET assemblies, Linux ELF (statically or dynamically linked), macOS Mach-O, Android APK / AAB / DEX / split bundles, iOS IPA / dylib. Format is auto-detected; the right pipeline routes itself.
- **Standalone CLI, no AI required** — `chimera analyze` runs the full pipeline headless and writes a project to disk.
- **Cross-layer call graph** — Java / Kotlin ↔ JNI ↔ native ARM64, unified into one model.

### Desktop / native RE
- **Multi-decompiler picker** — request r2 or Ghidra (or both, side-by-side) per function via the API or web UI; output is post-processed (DAT_/PTR_/FUN_/iVar/uVar → typed locals, Itanium C++ demangling, magic-constant labelling).
- **FLIRT-equivalent library naming** — masked-byte signature pack ships 176 prefixes covering libc / libssl / libcrypto / libz; matches typed against `arch + format` so x86_64 ELF and PE32+ don't cross-pollute. Static-linked stripped binaries get function names back automatically.
- **Persistent annotations** — rename functions, add per-address comments, set C-style type signatures, override classification. Stored in `overlay.json` per binary (atomic tempfile + rename), applied to the live model on every load.
- **Byte-level patching** — `BinaryPatcher` resolves VA→file-offset for PE (section table), ELF (PT_LOAD), and Mach-O (LC_SEGMENT_64). PE checksum is recomputed automatically. Five recipe kinds: write-bytes, nop-range, force-jump-taken (validates 0x70–0x7F short conditional jumps), find-import-and-stub (PE IAT walk), find-elf-plt-and-stub (.rela.plt / .dynsym). Three anti-debug bypass recipes ship out of the box.
- **Packer detection + UPX auto-unpack** — YARA-first (UPX / ASPack / VMProtect / Themida / MPRESS / PECompact / Enigma / MEW / kkrunchy), section-name fallback (UPX0, .vmpN, .themida, .aspack, …), per-section byte-entropy heuristic on executable sections. `chimera unpack` round-trips UPX byte-identically and ships manual guidance for the VM-protectors no open-source unpacker handles cleanly.
- **gdb bridge** — `chimera gdb-export` writes a `.gdbinit` of `$convenience` variables + a `chimera-bp` user command so `gdb` lands inside the same address space your renames refer to.
- **PE / ELF imports scoring** — PEStudio-style buckets (process injection, anti-debug, persistence, network, crypto, evasion). Linux: persistence-string scan (cron / systemd / `LD_PRELOAD` / init.d), syscall scoring, XOR-string heuristic.
- **.NET assemblies** — ILSpy decompilation per type when `ilspycmd` is on PATH; Ghidra fallback for mixed-mode (C++/CLI).

### Mobile RE
- **Framework detection** — React Native (Hermes / JSC), Flutter, Unity IL2CPP, Xamarin, Cordova / Capacitor.
- **Manifest + NSC hardening** — `chimera manifest app.apk` reports `android:debuggable`, `allowBackup` without rules, exported components without permissions, cleartext-traffic flags, `network_security_config.xml` issues (cleartext base/domain configs, user-CA trust). Each finding cites file and line.
- **Protection bypass** — root / jailbreak / Frida / debugger / packer detection with bundled bypass scripts. (Devices running `frida-server` must be jailbroken / rooted; `frida-gadget` is fine on a stock device.)
- **Dynamic attach** — `chimera attach --pid <pid>` (local) or `--target <pkg> --device <id>` (mobile) with multi-bypass preload, message drain, interactive REPL.

### Shared workflow
- **Static + dynamic** — Semgrep + YARA + capa for static; Frida for runtime confirmation.
- **Binary-vs-binary diff** — `chimera diff <a> <b>` reports added/removed permissions, exported components, SDKs, native libraries (with sha256), manifest + NSC findings (regression / resolution).
- **Reports** — JSON, HTML, Markdown, SARIF v2.1.0, CycloneDX 1.6 SBOM, MASVS coverage matrix, CVSS finding draft.
- **Web UI + TUI** — FastAPI-backed UI with Monaco editor (right-click rename / comment / set-type), Textual TUI for device interaction.
- **MCP server** — high-level analysis tools exposed to any MCP-compatible LLM client.
- **OWASP MASVS** — findings tagged with MASVS categories.

## Desktop reverse engineering

Chimera ships a desktop RE workflow that mirrors the muscle-memory of
IDA Pro / Ghidra / Binary Ninja, driven from the same CLI and the same
HTTP API as the mobile pipeline.

### What you get

| Workflow                                                  | How                                                                              |
| --------------------------------------------------------- | -------------------------------------------------------------------------------- |
| Open a PE / ELF / Mach-O / .NET binary, list functions    | `chimera analyze <file>`                                                         |
| Pick a decompiler per function (r2, Ghidra, or both)      | `GET /api/projects/{id}/functions/{addr}/decomp?backend=r2|ghidra|all`           |
| Rename, comment, set type — persisted across sessions     | `POST /api/projects/{id}/annotations/{rename,comment,type,classify}`             |
| Auto-name statically-linked library functions             | Phase 5.5 (ELF) / Phase 6.5 (PE) signature matcher, runs during `analyze`        |
| Patch a binary (raw bytes, recipes, or nop-range)         | `chimera patch <file> --addr 0x… --bytes 90909090`                               |
| Bypass `IsDebuggerPresent` / `CheckRemoteDebuggerPresent` / `ptrace` | `chimera patch <file> --recipe pe-isdebuggerpresent-nop --out patched.exe` |
| Hand the patched binary to `gdb` with your renames        | `chimera gdb-export <file> --out hello.gdbinit` then `gdb -x hello.gdbinit ./hello` |
| Detect + auto-unpack a packed binary                      | `chimera unpack <file>` (or `--detect-only` to inspect first)                    |
| Diff two cached projects                                  | `chimera diff <sha-a> <sha-b>`                                                   |
| Export findings as SARIF for CI                           | `chimera report <file> --format sarif`                                           |

### Quick start (desktop)

```bash
# Triage a PE
chimera analyze /path/to/sample.exe
chimera imports /path/to/sample.exe                   # bucket-grouped suspicious imports

# Triage a Linux ELF (statically linked → signature matcher fires)
chimera analyze /path/to/server.bin
chimera persistence /path/to/server.bin               # cron / systemd / LD_PRELOAD strings

# Patch out IsDebuggerPresent and save a clean copy
chimera patch /path/to/sample.exe --recipe pe-isdebuggerpresent-nop --out clean.exe

# Or patch raw bytes at a virtual address (dry-run first)
chimera patch /path/to/sample.exe --addr 0x140001000 --bytes 9090909090909090 --dry-run

# Detect packer + auto-unpack (UPX) — emits manual guidance for VM-protectors
chimera unpack /path/to/packed.bin
chimera unpack /path/to/packed.bin --detect-only

# Hand the analysis off to gdb
chimera gdb-export /path/to/server.bin --out server.gdbinit
gdb -x server.gdbinit /path/to/server.bin

# Open the web UI and right-click → "Rename function…" / "Add comment…"
chimera serve --port 8765
# then browse http://localhost:8765
```

### Interactive workflow (web UI)

Open a project, jump to a function, and the Monaco editor exposes
three right-click actions backed by the annotation API:

- **Rename function…** (F2) — persisted to `overlay.json`, re-applied
  on every reload, surfaces in subsequent decompilation passes.
- **Add comment on this line** — per-address comments keyed by line.
- **Set function signature…** — C-style prototype, used to retype
  arguments / return value in the post-processor.

Switch the decompiler dropdown between r2 and Ghidra to compare output
on the same function side by side.

### Library function naming (FLIRT-equivalent)

A 176-entry signature pack ships at
`src/chimera/data/sigs/libfn-x86_64.json`, masking call-target / RIP-relative
operands so the same prefix matches across compiler versions. Build
your own pack with `scripts/build_libfn_sigs.py` against any reference
library; the matcher runs after r2 triage so it only renames functions
the disassembler already extracted.

### Patch recipes

Three anti-debug bypass recipes ship bundled and are listed by
`chimera patch --list-recipes`:

- `pe-isdebuggerpresent-nop` — find kernel32!IsDebuggerPresent in the
  IAT, replace the function body with `xor eax, eax; ret`.
- `pe-checkremotedebuggerpresent-nop` — same for
  `CheckRemoteDebuggerPresent`.
- `elf-ptrace-zero` — walk `.rela.plt` / `.dynsym`, stub the `ptrace`
  PLT thunk so it returns 0 instead of calling through.

Add your own under `src/chimera/patching/recipe_packs/` — JSON, no code
required for the simple kinds.

### Optional tools

- `floss` (`pip install flare-floss`) — string deobfuscation for PE/ELF.
- `ilspycmd` (`dotnet tool install -g ilspycmd`) — .NET decompilation.
- `capa` (`pip install flare-capa`) — capability matching.
- `upx` (`apt-get install upx-ucl`) — auto-unpack for UPX-packed binaries.
- `gdb` — for the `gdb-export` handoff.

All optional; pipelines skip gracefully when a tool isn't installed.
The Docker image bundles all of the above except `floss`, `ilspycmd`
and `capa` (off by default to avoid dependency clashes — opt in with
`--build-arg INSTALL_CAPA=1`).

### Limitations

- **No Hex-Rays-quality decompiler.** Ghidra is good and the
  post-processor cleans it up, but for heavily-optimised C++ Hex-Rays
  is still the gold standard.
- **No interactive structure recovery** — you can rename and retype,
  but there's no "Edit → Structure" editor inside chimera yet.
- **No native debugger UX** — debugging happens via the gdb bridge, not
  inside chimera.
- No sandbox, no symbolic execution.
- Authenticode signatures are detected (presence) but not validated.
- Mixed-mode .NET (C++/CLI) falls back to Ghidra.

---

## Memory image triage (Linux)

Chimera analyzes Linux memory captures (LiME / raw) via Volatility 3.
Coverage:

- **Process tree** (`linux.pslist`, `linux.pstree`)
- **Recovered bash history** (`linux.bash`)
- **Open sockets** (`linux.sockstat`, falls back to `linux.netstat`)
- **Malfind RWX hits** (`linux.malfind`)
- **Kernel modules + rootkit indicators** (`linux.lsmod`,
  `linux.check_modules`, `linux.check_syscall`)
- **Persistence-relevant cached files** (`linux.pagecache.Files`
  cross-referenced against cron / systemd / `LD_PRELOAD` / init.d patterns)
- **Auto-stub IR findings** mapped to MITRE ATT&CK (T1014, T1055, T1543, T1071)

### Quick start

```sh
chimera memory /path/to/core.lime           # full pipeline + summary
chimera memory pslist /path/to/core.lime    # process list only
chimera memory netstat /path/to/core.lime   # connections only
chimera memory malfind /path/to/core.lime   # RWX hits only
chimera memory findings /path/to/core.lime  # IR findings (Markdown)
chimera report --format ir /path/to/core.lime --out report.ir.md
```

### Required tools

- **Volatility 3** (`pip install volatility3` or distro package). Make sure
  `vol` is on PATH. Volatility also needs Linux ISFs (kernel symbol tables)
  for the target image — see Volatility 3 docs.
- All optional; when `vol` is missing, the pipeline degrades to detection
  + format identification only.

### Limitations

- **Linux only** for now. Windows memory triage isn't wired up.
- **No symbolic execution / behavioral reconstruction.** Volatility
  output goes through Chimera's parsers as-is; deeper analysis is the
  analyst's job.
- **Memory-image fixtures are tiny synthetic stubs.** Real triage runs
  need GB-scale captures + matching ISF symbols.

---

## Status

Alpha. The CLI, pipelines, and adapter layer are usable; the web UI is
under active development and the database-backed project store is a
follow-up. Public APIs may move without warning until a tagged release.

---

## Architecture

```mermaid
flowchart TB
    subgraph Frontends
        CLI[CLI]
        Web[Web UI]
        TUI[TUI]
        MCP[MCP Server]
    end

    subgraph Core["Core Engine"]
        Engine[ChimeraEngine]
        Pipelines["Pipelines<br/>pe · elf · macho · android · ios · objc_xref · react_native"]
        ResMgr[ResourceManager]
        Cache[AnalysisCache]
        Overlay["Overlay<br/>renames · comments · types"]
        Patcher[BinaryPatcher]
        Unpack[Unpacking]
        SigDB[Signature DB]
    end

    subgraph Adapters["Backend Adapters"]
        R2[radare2]
        Ghidra[Ghidra]
        Jadx[jadx]
        Apktool[apktool]
        Frida[Frida]
        Semgrep[Semgrep]
        YARA[YARA]
        Capa[capa]
        Hermes[hermes-dec]
        ClassDump[class-dump]
        Swift[swift-demangle]
        Webcrack[webcrack]
        AFL[AFL++]
        UPX[upx]
        Gdb[gdb]
    end

    Model["Unified Program Model<br/>functions · strings · xrefs · findings"]
    Findings["Findings + Reports<br/>MASVS · SARIF"]

    CLI --> Engine
    Web --> Engine
    TUI --> Engine
    MCP --> Engine
    Engine --> Pipelines
    Engine --> ResMgr
    Engine --> Cache
    Engine --> Overlay
    Engine --> Patcher
    Engine --> Unpack
    Engine --> SigDB
    Pipelines --> Adapters
    Adapters --> Model
    Overlay --> Model
    SigDB --> Model
    Model --> Findings
```

## Analysis pipeline

```mermaid
flowchart LR
    Input[PE / ELF / Mach-O / .NET / APK / IPA] --> Detect{detect_platform}
    Detect -->|pe| PE[pe pipeline]
    Detect -->|elf| ELF[elf pipeline]
    Detect -->|macho| MO[mach-o pipeline]
    Detect -->|android| UnpackA[unpack_apk]
    Detect -->|ios| UnpackI[unpack_ipa]

    PE --> Sigs["Signature match<br/>(FLIRT-equivalent)"]
    ELF --> Sigs
    MO --> Triage
    UnpackA --> Framework[FrameworkDetector]
    UnpackI --> Framework
    Framework --> Triage["Triage<br/>radare2 + symbols"]
    Sigs --> Triage
    Triage --> Decompile["Decompile<br/>r2 · Ghidra · jadx · class-dump"]
    Decompile --> Overlay["Overlay<br/>renames · comments · types"]
    Overlay --> Static["Static analysis<br/>Semgrep + YARA + capa"]
    Static --> Confirm["Dynamic confirm<br/>Frida (optional)"]
    Confirm --> Report["Findings · MASVS · SARIF · SBOM"]
```

---

## Quick start

### Docker (recommended)

```bash
docker compose up -d
docker exec chimera chimera analyze /projects/app.apk
```

The image bundles pinned versions of radare2, jadx, and Ghidra. Mount your
binaries into `/projects/`:

```bash
docker run --rm -v "$PWD:/projects" chimera:latest analyze /projects/app.apk
```

### Local install

Requires Python 3.12+. External tools (radare2, jadx, Ghidra, Frida) are
discovered on `PATH` and gracefully skipped when absent.

```bash
git clone https://github.com/TyrusRC/chimera.git
cd chimera
pip install -e ".[dev]"

chimera info          # show backend availability
chimera analyze app.apk
```

---

## Usage

```bash
# Full pipeline on an APK / IPA
chimera analyze app.apk
chimera analyze app.ipa --ghidra-home /opt/ghidra

# Restore obfuscated identifiers via mapping.txt
chimera analyze app.apk --mapping-file release.mapping

# Detect protections (root / jailbreak / Frida / debugger / packer)
chimera detect-protections app.apk

# Manifest + NSC hardening findings (Android)
chimera manifest app.apk
chimera manifest app.apk --format json

# Compare two app versions
chimera analyze app-1.0.0.apk
chimera analyze app-1.1.0.apk
chimera diff <sha256-a> <sha256-b>            # markdown output
chimera diff <sha256-a> <sha256-b> --format json

# List third-party SDKs
chimera sdks app.apk

# Extract IoCs (URLs, IPs, hosts, paths, mailto) from cached analysis
chimera ioc app.apk

# List JNI bindings (Java native methods ↔ native symbols)
chimera jni app.apk

# List PE imports grouped by suspicious-imports bucket
chimera imports sample.exe

# Author a custom YARA rule against analyzed strings
chimera yara app.apk --rule-name my_rule

# Frida — list bundled bypass scripts, show one, or run on a device session
chimera frida list
chimera frida show ssl-pinning-bypass
chimera frida run --session <id> --script ssl-pinning-bypass

# Generate a report as SARIF (for SARIF-aware tooling)
chimera report app.apk --format sarif --out app

# Desktop RE — patch, gdb-export, unpack, attach
chimera patch sample.exe --list-recipes
chimera patch sample.exe --recipe pe-isdebuggerpresent-nop --out clean.exe
chimera patch sample.exe --addr 0x140001000 --bytes 9090909090909090 --dry-run

chimera gdb-export server.bin --out server.gdbinit
gdb -x server.gdbinit ./server.bin

chimera unpack packed.bin                # detect + auto-unpack (UPX)
chimera unpack packed.bin --detect-only  # inspect first; emits guidance for VM-protectors

chimera attach --pid 12345                                 # local process via Frida
chimera attach --target com.example.app --device usb       # mobile attach
chimera attach --pid 12345 --bypass anti_debug --interactive  # multi-bypass + REPL

# Connected devices
chimera devices

# Web UI (FastAPI)
chimera serve

# TUI for device operations
chimera tui

# MCP server (stdio — wire into Claude Desktop / Code)
chimera mcp
```

### MCP integration

Chimera exposes high-level tools (`analyze`, `xref`, `list_devices`,
`pull_app`, `run_semgrep`, `apply_bypass`, …) over MCP. Point any
MCP-compatible client at `chimera mcp` and the model can drive the
pipeline directly.

---

## Backend matrix

| Layer             | Backend         | Used for                                            |
| ----------------- | --------------- | --------------------------------------------------- |
| Native triage     | radare2         | functions, strings, xrefs, ObjC pool, r2 decompile  |
| Native deep       | Ghidra          | decompilation, type inference                       |
| .NET              | ilspycmd        | per-type C# decompilation (Ghidra fallback)         |
| Java / Kotlin     | jadx, apktool   | source recovery, manifest, resources                |
| iOS metadata      | class-dump      | ObjC class layout, protocols                        |
| Symbol demangle   | swift-demangle  | Swift identifier recovery                           |
| JS bundles        | webcrack        | bundled-JS unpacking                                |
| Hermes            | hermes-dec      | RN Hermes bytecode disassembly                      |
| Static rules      | Semgrep         | MASVS rules over decompiled sources                 |
| Pattern scanning  | YARA            | packer detection, malware fingerprints              |
| Capabilities      | capa            | high-level behavior tagging (optional)              |
| Dynamic           | Frida           | runtime hooks, bypass scripts, `chimera attach`     |
| Fuzzing           | AFL++           | native-library fuzzing harness                      |
| Unpacking         | upx             | UPX auto-unpack (UPX0 / UPX1)                       |
| Debugger handoff  | gdb             | `chimera gdb-export` consumes `.gdbinit`            |

Adapters live in [`src/chimera/adapters/`](src/chimera/adapters) and all
implement the `BackendAdapter` interface
([`base.py`](src/chimera/adapters/base.py)). Adding a new backend means
dropping one file and registering it in
[`core/engine.py`](src/chimera/core/engine.py).

---

## Development

```bash
pip install -e ".[dev]"
pytest                  # full suite
pytest tests/unit       # unit tests only
```

Layout:

```
src/chimera/
├── adapters/      # backend wrappers (radare2, Ghidra, jadx, Frida, ...)
├── api/           # FastAPI routes + websocket layer (incl. annotations, decomp, findings)
├── bypass/        # detection + Frida bypass orchestration
├── core/          # engine, config, cache, resource manager, overlay
├── data/sigs/     # FLIRT-equivalent library function signature packs
├── device/        # adb / libimobiledevice wrappers
├── frameworks/    # framework detection (RN, Flutter, Unity, Xamarin, ...)
├── model/         # UnifiedProgramModel + SQLite schema
├── parsers/       # Mach-O ObjC, ARM64 register tracking, function signatures
├── patching/      # BinaryPatcher, recipes, recipe packs
├── pipelines/     # platform-specific orchestration (pe, elf, macho, android, ios, ...)
├── report/        # JSON / HTML / SARIF / SBOM builders, decomp post-processor
├── unpacking/     # YARA + section + entropy detect; UPX shell-out; guidance
└── mcp_server.py  # MCP entrypoint
```

Contributions welcome. Open an issue for substantial work before sending
a PR so we can align on direction.

---

## License

[Apache License 2.0](LICENSE).
