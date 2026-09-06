"""Tool schemas advertised by the Chimera MCP server.

Kept apart from the handlers so the wire contract — the names, the
descriptions an LLM reads when choosing a tool, and the argument schemas
the framework validates against — can be read as one piece instead of
scrolling past forty implementations.
"""
from __future__ import annotations

from mcp.types import Tool


def all_tools() -> list[Tool]:
    """Every tool this server exposes, in presentation order."""
    return [
        # --- Session ---
        Tool(name="status",
             description="Show current session state: whether a binary is loaded, what backends are available, analysis stats. Call this first to understand what you can do.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="analyze",
             description="Run full static analysis on a mobile binary (APK/IPA). This is the entry point — must be called before query tools.",
             inputSchema={"type": "object", "properties": {
                 "path": {"type": "string", "description": "Absolute path to APK or IPA file"},
                 "mapping_file": {
                     "type": "string",
                     "description": "Optional ProGuard/R8 mapping.txt path to restore original identifiers",
                 },
             }, "required": ["path"]}),

        # --- Query: Code ---
        Tool(name="get_functions",
             description="List functions. Search by name, filter by classification/layer. Returns address, name, whether decompiled code exists.",
             inputSchema={"type": "object", "properties": {
                 "search": {"type": "string"}, "classification": {"type": "string"},
                 "layer": {"type": "string", "enum": ["native", "java", "objc", "dart", "js"]},
                 "offset": {"type": "integer", "default": 0},
                 "limit": {"type": "integer", "default": 50},
             }}),
        Tool(name="get_function",
             description="Get full detail for one function: decompiled source, callers, callees.",
             inputSchema={"type": "object", "properties": {
                 "address": {"type": "string", "description": "Function address (e.g. 0x1234)"},
             }, "required": ["address"]}),
        Tool(name="get_strings",
             description="Search strings extracted from the binary. Supports regex patterns.",
             inputSchema={"type": "object", "properties": {
                 "pattern": {"type": "string", "description": "Regex pattern to filter strings"},
                 "offset": {"type": "integer", "default": 0},
                 "limit": {"type": "integer", "default": 100},
             }}),
        Tool(name="get_callgraph",
             description="Get call graph around a function (callers + callees) up to specified depth.",
             inputSchema={"type": "object", "properties": {
                 "address": {"type": "string"}, "depth": {"type": "integer", "default": 2},
                 "max_nodes": {"type": "integer", "default": 200,
                               "description": "Cap on nodes returned; response sets truncated=true if hit."},
             }, "required": ["address"]}),
        Tool(name="get_manifest",
             description="Get the decoded AndroidManifest.xml content (Android only). Useful for reviewing permissions, components, intent-filters.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="get_manifest_findings",
             description="AndroidManifest + network_security_config findings (debuggable, allowBackup, exported components, cleartext traffic, user-CA trust). Requires a prior analyze(path=...) call so the manifest XML is in cache.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="diff_projects",
             description=(
                 "Diff two cached chimera projects. Returns added/removed permissions, "
                 "exported components, SDK packages, native libs, and manifest+NSC findings. "
                 "Inputs are sha256 hashes or prefixes (>=8 chars). Both projects must be "
                 "cached — call analyze(path=...) on each first."
             ),
             inputSchema={"type": "object",
                          "properties": {
                              "a": {"type": "string", "description": "sha256 or prefix of project A"},
                              "b": {"type": "string", "description": "sha256 or prefix of project B"},
                          },
                          "required": ["a", "b"]}),

        # --- Detection ---
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

        # --- Actions ---
        Tool(name="get_bypass_scripts",
             description="Get Frida bypass scripts for detected protections. Returns a combined JS script ready to load via Frida.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="get_dynamic_hooks",
             description="Get Frida hook script for capturing runtime-loaded code (DexClassLoader, dlopen, System.loadLibrary).",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="pull_app",
             description="Pull an installed app from a connected device. Returns path to the downloaded APK/IPA.",
             inputSchema={"type": "object", "properties": {
                 "device_id": {"type": "string", "description": "Device ID from list_devices"},
                 "package": {"type": "string", "description": "Package name (e.g. com.example.app)"},
             }, "required": ["device_id", "package"]}),
        Tool(name="run_semgrep",
             description="Run Semgrep SAST rules on decompiled sources. Requires semgrep installed and a prior analyze call with jadx.",
             inputSchema={"type": "object", "properties": {
                 "rules": {"type": "string", "default": "auto", "description": "Semgrep rule config (auto, p/java, path to rules)"},
             }}),

        # --- Devices ---
        Tool(name="list_devices",
             description="List connected Android (ADB) and iOS (libimobiledevice) devices.",
             inputSchema={"type": "object", "properties": {}}),

        # --- Source & Artifact Browsing ---
        Tool(name="list_source_files",
             description="List decompiled source files from jadx output. Browse by package path. Essential for reading Java/Kotlin source after analysis.",
             inputSchema={"type": "object", "properties": {
                 "path": {"type": "string", "default": "", "description": "Relative path within jadx sources (e.g. 'com/example/app'). Empty for root."},
                 "pattern": {"type": "string", "description": "Glob pattern to filter files (e.g. '*.java', '**/*Activity*')"},
             }}),
        Tool(name="read_source",
             description="Read a decompiled source file from jadx output. Use list_source_files to find paths first.",
             inputSchema={"type": "object", "properties": {
                 "path": {"type": "string", "description": "Relative path within jadx sources (e.g. 'com/example/app/MainActivity.java')"},
                 "offset": {"type": "integer", "default": 0, "description": "Line offset to start reading from"},
                 "limit": {"type": "integer", "default": 200, "description": "Max lines to return"},
             }, "required": ["path"]}),
        Tool(name="read_cache",
             description="Read a cached analysis artifact (r2 triage, Ghidra output, jadx summary). Use list_artifacts to find keys.",
             inputSchema={"type": "object", "properties": {
                 "category": {"type": "string", "description": "Cache key (e.g. 'triage', 'r2_libnative.so', 'ghidra_libnative.so', 'jadx')"},
             }, "required": ["category"]}),
        Tool(name="list_artifacts",
             description="List all cached analysis artifacts and on-disk outputs for the current binary.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="get_disassembly",
             description="Get disassembly instructions for a function by address. Paged: use offset/limit for long functions.",
             inputSchema={"type": "object", "properties": {
                 "address": {"type": "string", "description": "Function address (e.g. 0x1234)"},
                 "offset": {"type": "integer", "default": 0},
                 "limit": {"type": "integer", "default": 200},
             }, "required": ["address"]}),
        Tool(name="get_class_headers",
             description="Read ObjC class-dump headers from iOS analysis. Lists header files or reads a specific header.",
             inputSchema={"type": "object", "properties": {
                 "file": {"type": "string", "description": "Header filename to read (e.g. 'AppDelegate.h'). Omit to list all headers."},
             }}),
        Tool(name="objc_xref",
             description=(
                 "Query the ObjC cross-reference graph (iOS only). Pass selector alone "
                 "to find all classes implementing it. Pass class_name+selector to scope "
                 "the lookup. Pass imp_address to query by IMP address — if imp_address "
                 "is given, selector/class_name are ignored. Returns matching methods "
                 "with callers, category, protocol, and class-dump-enriched signatures. "
                 "Use this instead of get_functions/get_class_headers when you need "
                 "selector → implementation → caller lookups."
             ),
             inputSchema={"type": "object", "properties": {
                 "selector": {"type": "string", "description": "ObjC selector, e.g. 'authenticate:'"},
                 "class_name": {"type": "string", "description": "Optional class to scope"},
                 "imp_address": {"type": "string", "description": "Optional IMP address"},
             }}),
        # --- Device Interaction ---
        Tool(name="list_packages",
             description="List installed packages/apps on a connected device.",
             inputSchema={"type": "object", "properties": {
                 "device_id": {"type": "string", "description": "Device ID from list_devices"},
             }, "required": ["device_id"]}),
        Tool(name="get_logcat",
             description="Get Android logcat output filtered by package. Useful for observing runtime behavior.",
             inputSchema={"type": "object", "properties": {
                 "device_id": {"type": "string", "description": "Device ID"},
                 "package": {"type": "string", "description": "Package name to filter logs for"},
                 "lines": {"type": "integer", "default": 100, "description": "Number of log lines"},
             }, "required": ["device_id", "package"]}),
        Tool(name="setup_proxy",
             description="Configure HTTP proxy on an Android device for traffic interception (e.g. Burp Suite).",
             inputSchema={"type": "object", "properties": {
                 "device_id": {"type": "string"}, "host": {"type": "string"}, "port": {"type": "integer"},
             }, "required": ["device_id", "host", "port"]}),
        Tool(name="clear_proxy",
             description="Remove HTTP proxy configuration from an Android device.",
             inputSchema={"type": "object", "properties": {
                 "device_id": {"type": "string"},
             }, "required": ["device_id"]}),

        # --- Frida Dynamic Analysis ---
        Tool(name="start_frida_server",
             description="Start frida-server on a connected device (requires root/jailbreak). Must be called before frida_attach/frida_spawn.",
             inputSchema={"type": "object", "properties": {
                 "device_id": {"type": "string", "description": "Device ID"},
             }, "required": ["device_id"]}),
        Tool(name="frida_spawn",
             description="Spawn an app with Frida instrumentation. Optionally inject a script (e.g. bypass script from get_bypass_scripts).",
             inputSchema={"type": "object", "properties": {
                 "package": {"type": "string", "description": "Package name to spawn"},
                 "device_id": {"type": "string", "description": "Device ID (optional, uses USB device if omitted)"},
                 "script": {"type": "string", "description": "JavaScript source to inject at spawn"},
             }, "required": ["package"]}),
        Tool(name="frida_attach",
             description="Attach Frida to a running app process for live instrumentation.",
             inputSchema={"type": "object", "properties": {
                 "target": {"type": "string", "description": "Package name or PID to attach to"},
                 "device_id": {"type": "string", "description": "Device ID (optional)"},
             }, "required": ["target"]}),
        Tool(name="frida_exec",
             description="Execute JavaScript code in an active Frida session. Use to call RPC exports or run ad-hoc hooks.",
             inputSchema={"type": "object", "properties": {
                 "session_key": {"type": "string", "description": "Session key (package name or PID used in attach/spawn)"},
                 "code": {"type": "string", "description": "JavaScript code to evaluate"},
             }, "required": ["session_key", "code"]}),
        Tool(name="frida_load_script",
             description="Load a Frida script into an active session. Use with bypass scripts or custom hooks.",
             inputSchema={"type": "object", "properties": {
                 "session_key": {"type": "string", "description": "Session key from frida_attach/frida_spawn"},
                 "script": {"type": "string", "description": "JavaScript source code to load"},
             }, "required": ["session_key", "script"]}),
        Tool(name="frida_messages",
             description="Get all Frida messages from an active session. Shows hook output, code capture events, errors.",
             inputSchema={"type": "object", "properties": {
                 "session_key": {"type": "string", "description": "Session key"},
                 "since": {"type": "integer", "default": 0, "description": "Return messages after this index"},
             }, "required": ["session_key"]}),
        Tool(name="frida_detach",
             description="Detach from a Frida session and clean up.",
             inputSchema={"type": "object", "properties": {
                 "session_key": {"type": "string", "description": "Session key to detach"},
             }, "required": ["session_key"]}),

        # --- Fuzzing ---
        Tool(name="start_fuzz",
             description="Start an AFL++ fuzzing campaign on a native library. Requires afl-fuzz installed.",
             inputSchema={"type": "object", "properties": {
                 "binary": {"type": "string", "description": "Path to native binary/library to fuzz"},
                 "input_dir": {"type": "string", "description": "Directory with seed inputs"},
                 "output_dir": {"type": "string", "description": "Directory for fuzzing output"},
                 "duration": {"type": "integer", "default": 300, "description": "Fuzzing duration in seconds"},
                 "qemu": {"type": "boolean", "default": True, "description": "Use QEMU mode for ARM binaries"},
             }, "required": ["binary", "input_dir", "output_dir"]}),
        Tool(name="fuzz_status",
             description="Check status and results of a running or completed fuzzing campaign.",
             inputSchema={"type": "object", "properties": {
                 "campaign_id": {"type": "string", "description": "Campaign ID from start_fuzz result"},
             }, "required": ["campaign_id"]}),

        # --- .NET dynamic tracing ---
        Tool(name="dotnet_trace",
             description=(
                 "Run a Windows .NET assembly on Linux and hook methods at "
                 "runtime with Harmony, to defeat VM-protection / anti-tamper "
                 "that beats static analysis. Harmony detours JIT'd native "
                 "code, not on-disk IL, so an IL-integrity check does not see "
                 "the hooks. Hook the inner comparator or the VM memory-read "
                 "primitive, not the outer validator. Reports byte[]/string "
                 "values seen plus any int/char stream a method moves — a VM "
                 "read primitive's return stream reconstructs the target key. "
                 "Does not modify the target file."),
             inputSchema={"type": "object", "properties": {
                 "path": {"type": "string", "description": "Absolute path to the .NET assembly (.exe/.dll)"},
                 "methods": {"type": "array", "items": {"type": "string"},
                             "description": "Methods to hook: a bare name hooks it in the target; TYPE::NAME (e.g. System.String::op_Equality) hooks a BCL method."},
                 "inputs": {"type": "array", "items": {"type": "string"},
                            "description": "Lines fed to stdin in order — one per menu step to reach the key prompt."},
                 "neutralize_pinvoke": {"type": "boolean", "default": True,
                                        "description": "Stub kernel32/ntdll so a Windows binary runs on Linux and its anti-debug imports read clean."},
                 "timeout": {"type": "integer", "default": 120},
             }, "required": ["path", "methods"]}),

        # --- Annotate (write-back) ---
        # These persist the driving model's findings into the per-binary
        # overlay.json (atomic) and update the live model. Read them back
        # with get_function / list_annotations. This is the only write path
        # in the MCP surface — everything else is read-only.
        Tool(name="rename_function",
             description="Rename the function at ADDRESS. Persists to the project overlay and updates the live model, so the next get_function shows the new name. Survives restart.",
             inputSchema={"type": "object", "properties": {
                 "address": {"type": "string", "description": "Function address (e.g. 0x1234)"},
                 "name": {"type": "string", "description": "New function name"},
             }, "required": ["address", "name"]}),
        Tool(name="set_comment",
             description="Attach a comment at ADDRESS (line 0 = function header). Persisted to the overlay. Use it to record what a routine does as you understand it.",
             inputSchema={"type": "object", "properties": {
                 "address": {"type": "string", "description": "Function address (e.g. 0x1234)"},
                 "text": {"type": "string", "description": "Comment body"},
                 "line": {"type": "integer", "default": 0,
                          "description": "Line/offset within the function; 0 = header/global comment"},
             }, "required": ["address", "text"]}),
        Tool(name="set_function_type",
             description="Pin a C-style signature on the function at ADDRESS (e.g. 'int decode_license(char*)'). Persisted; updates the live model's signature.",
             inputSchema={"type": "object", "properties": {
                 "address": {"type": "string", "description": "Function address (e.g. 0x1234)"},
                 "signature": {"type": "string", "description": "Free-form C signature"},
             }, "required": ["address", "signature"]}),
        Tool(name="set_classification",
             description="Override the classification of the function at ADDRESS (e.g. 'crypto', 'anti_debug', 'license_check'). Persisted; updates the live model.",
             inputSchema={"type": "object", "properties": {
                 "address": {"type": "string", "description": "Function address (e.g. 0x1234)"},
                 "classification": {"type": "string", "description": "Classification label"},
             }, "required": ["address", "classification"]}),
        Tool(name="add_note",
             description="Record a narrative finding in the project notebook, optionally with evidence links to addresses. Survives export/import. Use it to write up how a protection works or how you cracked it.",
             inputSchema={"type": "object", "properties": {
                 "title": {"type": "string"},
                 "body": {"type": "string", "default": ""},
                 "tags": {"type": "array", "items": {"type": "string"}},
                 "evidence": {"type": "array", "items": {"type": "object", "properties": {
                     "address": {"type": "string"}, "line": {"type": "integer"}}},
                     "description": "Evidence items: {address, line}"},
             }, "required": ["title"]}),
        Tool(name="list_annotations",
             description="List every annotation recorded for the loaded binary: renames, comments, types, classifications, notes. Use it to audit what you've already recorded before continuing.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="batch_annotate",
             description="Apply many annotations in one atomic write — far fewer round-trips than one call each when documenting a whole binary. Each op is {op, address, ...}: op='rename' needs 'name'; 'comment' needs 'text' (+optional 'line'); 'type' needs 'signature'; 'classify' needs 'classification'; 'rename_variable' needs 'original'+'new_name'. One bad op is reported, the rest still apply.",
             inputSchema={"type": "object", "properties": {
                 "ops": {"type": "array", "items": {"type": "object", "properties": {
                     "op": {"type": "string",
                            "enum": ["rename", "comment", "type", "classify", "rename_variable"]},
                     "address": {"type": "string"},
                     "name": {"type": "string"}, "text": {"type": "string"},
                     "line": {"type": "integer"}, "signature": {"type": "string"},
                     "classification": {"type": "string"},
                     "original": {"type": "string"}, "new_name": {"type": "string"},
                 }, "required": ["op"]}},
             }, "required": ["ops"]}),

        # --- Emulation ---
        Tool(name="emulate_function",
             description="Emulate the function at ADDRESS in isolation (Unicorn) with integer args and read back memory it writes — resolve a hash, run a string-decrypt or checksum routine without running the whole binary. Self-contained leaf routines only: a call into an import/syscall hits unmapped memory and stops. Needs the 'emulate' extra; arch defaults to the loaded binary's (x86_64/arm64).",
             inputSchema={"type": "object", "properties": {
                 "address": {"type": "string", "description": "Function address (e.g. 0x1234)"},
                 "args": {"type": "array", "items": {"type": "integer"},
                          "description": "Integer arguments in register order (rdi.. / x0..)."},
                 "arch": {"type": "string", "enum": ["x86_64", "arm64"],
                          "description": "Override the arch; defaults to the loaded binary's."},
                 "read_back": {"type": "array", "items": {"type": "object", "properties": {
                     "address": {"type": "string"}, "length": {"type": "integer"}}},
                     "description": "Memory regions to return after the run: {address, length}."},
                 "max_insns": {"type": "integer", "default": 200000},
             }, "required": ["address"]}),

        # --- Host hardware ---
        Tool(name="detect_gpu",
             description="Report the host's GPU and GPU-capable crackers (hashcat/john) and whether GPU-accelerated cracking is available. Call this before attempting any hash-crack, password/keyspace brute-force, or encrypted-archive attack to decide whether to offload to the GPU. Returns gpus, cracker info, a 'usable' verdict, and a hint. Read-only; needs no loaded binary.",
             inputSchema={"type": "object", "properties": {}}),

        # --- Configuration ---
        Tool(name="get_config",
             description="Get or modify Chimera analysis configuration. Call with no params to read current config.",
             inputSchema={"type": "object", "properties": {
                 "set": {"type": "object", "description": "Key-value pairs to update (e.g. {\"skip_dynamic\": false, \"ghidra_max_mem\": \"8g\"})"},
             }}),
    ]
