"""MCP tool schemas: framework/protection/SDK/protocol detection + capability & string scans."""
from __future__ import annotations

from mcp.types import Tool


def tools() -> list[Tool]:
    return [
        Tool(name="get_info",
             description="Get binary metadata: platform, framework, format, SHA256, size, package name.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="detect_protections",
             description="Detect active security protections: root/jailbreak detection, anti-Frida, anti-debug, SSL pinning, integrity checks.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="detect_sdks",
             description="Fingerprint third-party SDKs from function package names.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="detect_framework",
             description="Get detected cross-platform framework (Flutter, React Native, Xamarin, Unity, Cordova, or native).",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="detect_protocols",
             description="Detect API protocols (REST, gRPC, GraphQL, WebSocket, Protobuf) and extract endpoints from strings.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="detect_gpu",
             description="Report the host's GPU and GPU-capable crackers (hashcat/john) and whether GPU-accelerated cracking is available. Call this before attempting any hash-crack, password/keyspace brute-force, or encrypted-archive attack to decide whether to offload to the GPU. Returns gpus, cracker info, a 'usable' verdict, and a hint. Read-only; needs no loaded binary.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="detect_capabilities",
             description="Run Mandiant capa to detect code-level capabilities in an ELF/Mach-O binary and map them to MITRE ATT&CK techniques and Malware Behavior Catalog (MBC) IDs — answers 'what can this sample DO?' (e.g. 'create TCP socket', 'inject into process', 'encrypt via RC4'). Returns the capability list per rule (namespace, scope, attack, mbc, match addresses). Needs the capa CLI (pip install flare-capa); offline, no API key. Optional backend (vivisect default; pyghidra/binja faster if available).",
             inputSchema={"type": "object", "properties": {
                 "target": {"type": "string", "description": "Path to the binary."},
                 "rules_dir": {"type": "string", "description": "Optional custom capa rules directory."},
                 "backend": {"type": "string", "description": "capa static backend (vivisect|pyghidra|binja|ida)."},
             }, "required": ["target"]}),
        Tool(name="deobfuscate_strings",
             description="Run Mandiant FLOSS to recover strings that plain get_strings misses: STACK strings (built byte-by-byte), TIGHT strings (built in a loop), and DECODED strings (emulated through the deobfuscation routine) — where malware hides its C2, mutexes, paths and keys. Returns the decoded/stack/tight categories with counts. Needs the floss CLI (pip install flare-floss); decoded-string emulation is the slow part.",
             inputSchema={"type": "object", "properties": {
                 "target": {"type": "string", "description": "Path to the binary."},
                 "timeout": {"type": "integer", "default": 90},
             }, "required": ["target"]}),
        Tool(name="yara_scan",
             description="Scan a file (sample/dump/unpacked payload) against YARA rules on demand — the compiled-binary counterpart to run_semgrep's source patterns, for identifying family/packer/capability/IOC. Uses chimera's bundled rule set plus any rules in an optional rules_dir. Returns hits with rule name, tags, meta and matched string identifiers. Needs yara-python. (To AUTHOR a rule from findings, use the `chimera yara` CLI.)",
             inputSchema={"type": "object", "properties": {
                 "target": {"type": "string", "description": "Path to the file to scan."},
                 "rules_dir": {"type": "string", "description": "Optional directory of extra .yar/.yara rules, added to the bundled set."},
             }, "required": ["target"]}),
        Tool(name="run_semgrep",
             description="Run Semgrep SAST rules on decompiled sources. Requires semgrep installed and a prior analyze call with jadx.",
             inputSchema={"type": "object", "properties": {
                 "rules": {"type": "string", "default": "auto", "description": "Semgrep rule config (auto, p/java, path to rules)"},
             }}),
        Tool(name="get_bypass_scripts",
             description="Get Frida bypass scripts for detected protections. Returns a combined JS script ready to load via Frida.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="get_dynamic_hooks",
             description="Get Frida hook script for capturing runtime-loaded code (DexClassLoader, dlopen, System.loadLibrary).",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="macho_codesign",
             description="Read a Mach-O's code signature — the CodeDirectory **identifier** + CDHash — and list/extract its universal (fat) slices. The identifier is an analyst signal: an author can label which fat slice is the real one through it (FLARE-On 13 ch3: the real Crystal slice signs as `true_honest_flag`, the decoy as `totally_fake_flag`), and for malware it's the bundle id. Returns one entry per arch (thin → one, fat → one per slice) with {arch_offset, identifier, cdhash, hash_type, has_signature}. Pass `extract_slice` (index) [+ `out_path`] to write that slice out as a standalone thin Mach-O. Read-only except the optional extract.",
             inputSchema={"type": "object", "properties": {
                 "path": {"type": "string", "description": "Mach-O (thin or fat/universal) to read."},
                 "extract_slice": {"type": "integer", "description": "Fat-slice index to extract (optional)."},
                 "out_path": {"type": "string", "description": "Where to write the extracted slice (default <path>.sliceN)."},
             }, "required": ["path"]}),
    ]
