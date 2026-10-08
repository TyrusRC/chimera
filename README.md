# Chimera

> Reverse-engineering platform for desktop and mobile binaries. Many backends, one interface.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB.svg?logo=python&logoColor=white)](pyproject.toml)
[![Platform](https://img.shields.io/badge/platform-PE%20%7C%20ELF%20%7C%20Mach--O%20%7C%20.NET%20%7C%20Android%20%7C%20iOS-success.svg)](#features)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED.svg?logo=docker&logoColor=white)](Dockerfile)
[![MCP](https://img.shields.io/badge/MCP-compatible-5A4FCF.svg)](src/chimera/mcp_server.py)

Chimera is a unified wrapper around Ghidra, radare2, jadx, Frida, capa, YARA and
a growing set of platform-specific tools. It analyzes Windows PE / .NET, Linux
ELF, macOS Mach-O, Android APKs and iOS IPAs through one CLI, one project store
and one HTTP API — no LLM required — and exposes an MCP server so Claude or any
compatible model can drive the pipeline.

## Features

- **Cross-platform static analysis** — PE / .NET, ELF, Mach-O, APK, IPA, WASM and
  firmware: triage → decompile → annotate → patch → export.
- **Desktop / native RE** — r2 and Ghidra decompilers, a FLIRT-style
  library-function matcher, persistent renames/comments/types, byte-level
  patching with anti-debug recipes, UPX auto-unpack, packer detection, and a gdb
  symbol bridge.
- **Mobile RE** — APK/IPA pipeline, manifest/NSC hardening findings, protection
  detection (root/jailbreak/Frida/debugger/packer), Frida instrumentation, and
  Flutter (B(l)utter) / React Native (Hermes) extraction.
- **Solving primitives** — symbolic execution (angr), emulation (unicorn), CFG
  deflattening, dispatch-table recovery, crypto/RSA/AES helpers, YARA solving.
- **Memory & firmware** — Volatility memory triage, UEFI firmware carving, ELF
  core-dump triage.
- **AI-assisted (optional, opt-in)** — LLM-backed decompiler refinement and
  naming, VarBERT variable recovery, and the EMBER malware classifier. None of
  this runs on the default `analyze` path.

## Install

Chimera runs on bare metal. Requires Python 3.12+. External tools (radare2,
jadx, Ghidra, Frida, …) are discovered on `PATH` and skipped gracefully when
absent.

```bash
git clone https://github.com/TyrusRC/chimera.git
cd chimera
scripts/setup.sh --native   # installs chimera[dev] into .venv (uv when available)
```

`scripts/setup.sh --native` can `apt-get install` the free system tools
(radare2, upx-ucl, gdb); add `--yes` to skip prompts.

```bash
chimera doctor          # external-tool + environment health check, with install hints
chimera analyze app.apk
chimera install         # register chimera with your MCP agent hosts
```

### Docker (isolation sandbox)

For reversing an untrusted target in a disposable environment. The image bundles
pinned radare2, jadx and Ghidra:

```bash
docker compose up -d
docker run --rm -v "$PWD:/projects" chimera:latest analyze /projects/app.apk
```

## Usage

```bash
chimera analyze app.apk                    # full pipeline (PE/ELF/Mach-O/APK/IPA)
chimera analyze app.ipa --ghidra-home /opt/ghidra
chimera detect-protections app.apk         # root/jailbreak/Frida/debugger/packer
chimera manifest app.apk --format json     # Android manifest + NSC findings
chimera diff <sha-a> <sha-b>               # compare two analyses
chimera sdks app.apk                        # third-party SDKs
chimera patch target.exe --nop 0x401000    # byte/asm patching (dry-run by default)
```

Run `chimera --help` for the full command set.

## MCP

Chimera exposes an MCP server so an agent (Claude Code or any MCP client) can
drive the whole pipeline — analysis, decompilation, patching, dynamic
instrumentation, and the solving primitives above. Register it with `chimera
install`.

## Optional tools

Everything beyond the core decompilers is optional and auto-detected — a missing
tool returns an install hint, never a failure. Install the Python extras you
need:

```bash
pip install "chimera[emulate,disasm,solve,patch,capa,pdf,firmware]"
```

Run `chimera doctor` for the full tool + extra inventory.

## License

[Apache License 2.0](LICENSE).
