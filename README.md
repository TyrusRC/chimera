# Chimera

Mobile reverse engineering platform. Many backends, one beast.

Chimera combines Ghidra, Radare2, Frida, and 20+ specialized tools into a
unified wrapper for Android and iOS app security analysis. Works standalone
as a CLI — no AI required. Optional MCP layer lets Claude or any LLM act as
a commander.

## Features

- **Autonomous analysis** — full pipeline runs without AI: unpack, triage, decompile, detect, confirm
- **Zero false positives** — static detect, dynamic confirm, report only verified findings
- **Mobile-only** — optimized exclusively for Android (APK/DEX/ARM) and iOS (IPA/Mach-O/ARM64)
- **Cross-layer analysis** — unified Java/Kotlin ↔ JNI ↔ native call graph
- **Security bypass** — auto-detect and bypass root/jailbreak/frida/debug/packer protections
- **Cross-platform frameworks** — Flutter, React Native, Xamarin, Unity IL2CPP, Cordova
- **Professional UI** — Web UI (IDA Pro-like) + TUI for device operations
- **MCP integration** — Claude drives analysis via ~15 high-level commands
- **OWASP MASVS** — findings mapped to MASVS categories with SARIF output

## Quick Start

```bash
# Docker (recommended)
docker compose up -d
docker exec chimera analyze /projects/app.apk

# Local install
pip install -e ".[dev]"
chimera analyze app.apk
chimera info
```

## Architecture

```
CLI / Web UI / TUI / MCP
        ↓
   Core Engine (orchestrator)
        ↓
   Backend Adapters (pluggable)
   ├── Ghidra (deep decompilation)
   ├── Radare2 (fast triage)
   ├── jadx (Java/Kotlin)
   ├── Frida (dynamic)
   ├── AFL++ (fuzzing)
   └── 15+ more...
        ↓
   Unified Program Model (SQLite)
        ↓
   Findings + Report Engine
```

## License

Apache 2.0 — see [LICENSE](LICENSE)
