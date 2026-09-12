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
        Tool(name="connect_device",
             description="Attach a networked Android device or emulator over TCP/IP via `adb connect` (adb-over-Wi-Fi to a real ROOT device, or a remote/headless emulator). USB devices and locally-running emulators already appear in list_devices without this. A bare host uses the default adb port :5555. Returns {connected, target, devices, hint}; set disconnect=true to `adb disconnect` instead. The call is time-bounded (adb connect blocks on an unreachable target).",
             inputSchema={"type": "object", "properties": {
                 "target": {"type": "string", "description": "host[:port] to connect (bare host → :5555)."},
                 "disconnect": {"type": "boolean", "default": False, "description": "Disconnect the target instead of connecting."},
             }, "required": ["target"]}),

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
             description="Emulate the function at ADDRESS in isolation (Unicorn) with integer args and read back memory it writes — resolve a hash, run a string-decrypt or checksum routine without running the whole binary. Default maps only the function's own bytes, so a call into an import/syscall stops the run (self-contained leaf routines). Set full_image=true (x86-64 PE) to map the WHOLE image, stub any call that leaves the code sections as a ret, lazily back faults, and capture printable writes (a decrypted flag/message) — this runs an obfuscated computed-goto/MBA VM whose dispatch reads a data blob, and uses the MS x64 ABI (rcx,rdx,r8,r9). With input_buffers (full_image) it also acts as a buffer-in/buffer-out oracle for a decompressor / string-decryptor / hash-of-buffer routine: inject the input blob at a scratch VA, point an arg register (e.g. rcx/r8) at it, reserve a zeroed output VA, run, and read the plaintext with read_back — the way to recover a custom decompressor's output without identifying the algorithm. Pass path=... to emulate a bare binary with no prior analyze(). Needs the 'emulate' extra (and pefile for full_image).",
             inputSchema={"type": "object", "properties": {
                 "address": {"type": "string", "description": "Function address (e.g. 0x1234)"},
                 "path": {"type": "string", "description": "Emulate this binary directly (no analyze() needed); defaults to the loaded binary."},
                 "args": {"type": "array", "items": {"type": "integer"},
                          "description": "Integer arguments in register order (full_image: rcx,rdx,r8,r9; else rdi.. / x0..). Point one at an input_buffers VA to pass a pointer."},
                 "arch": {"type": "string", "enum": ["x86_64", "arm64"],
                          "description": "Override the arch; defaults to the loaded binary's. Ignored when full_image (x86-64 only)."},
                 "full_image": {"type": "boolean", "default": False,
                                "description": "Map the entire PE, stub external calls, lazily map faults, capture printable writes — for obfuscated VMs."},
                 "read_back": {"type": "array", "items": {"type": "object", "properties": {
                     "address": {"type": "string"}, "length": {"type": "integer"}}},
                     "description": "Memory regions to return after the run: {address, length}."},
                 "input_buffers": {"type": "array", "items": {"type": "object", "properties": {
                     "address": {"type": "string"}, "hex": {"type": "string"}}},
                     "description": "Bytes to write at a scratch VA before the run (full_image): {address, hex}. Passing any sets the first arg (rcx) from `args` instead of a fake `this`, so rcx can be a real pointer."},
                 "max_insns": {"type": "integer", "default": 200000},
             }, "required": ["address"]}),

        # --- Host hardware ---
        Tool(name="detect_gpu",
             description="Report the host's GPU and GPU-capable crackers (hashcat/john) and whether GPU-accelerated cracking is available. Call this before attempting any hash-crack, password/keyspace brute-force, or encrypted-archive attack to decide whether to offload to the GPU. Returns gpus, cracker info, a 'usable' verdict, and a hint. Read-only; needs no loaded binary.",
             inputSchema={"type": "object", "properties": {}}),

        # --- Static unpacking ---
        Tool(name="py_unwrap",
             description="Recursively peel marshal/zlib/base64/base85/bz2/lzma layers from a .py/.pyc/blob and dump the version-independent co_names/co_consts tree for every code object found; read-only, never executes the target. Use for obfuscated/packed Python — a .py that exec()s a marshalled/compressed/encoded blob, or nested-encoded bytecode. Set disasm to also disassemble each recovered code node (uses xdis for cross-version when installed).",
             inputSchema={"type": "object", "properties": {
                 "path": {"type": "string", "description": "Path to the .py / .pyc / blob file."},
                 "disasm": {"type": "boolean", "default": False,
                            "description": "Also disassemble each recovered code node."},
             }, "required": ["path"]}),

        Tool(name="pdf_tour",
             description="Statically triage a PDF: recover objects even with no xref/EOF (which strict parsers refuse), flag parser-differential traps (duplicate /Root, name-hex-obfuscated keys like /#52#6F#6F#74, duplicate/commented objects, missing xref/EOF), and — when the file uses the Standard security handler (R2-R6, RC4/AESV2/AESV3) — derive the key from the empty or supplied password, decrypt the streams, and list/dump any hidden inline images. Read-only; never renders or executes the document. Use for suspicious/malformed/encrypted PDFs.",
             inputSchema={"type": "object", "properties": {
                 "path": {"type": "string", "description": "Path to the PDF file."},
                 "password": {"type": "string", "default": "",
                              "description": "User/owner password to try (default: empty)."},
                 "extract_images_dir": {"type": "string",
                              "description": "Directory to write any inline images to."},
             }, "required": ["path"]}),

        Tool(name="evm_tour",
             description="Statically triage EVM smart-contract bytecode (as a hex string or a path to a hex/binary file) WITHOUT an Ethereum node: split a constructor (deploy) blob to its runtime, strip the solc metadata trailer, recover the dispatcher's 4-byte function selectors, and disassemble. Optionally pass calldata (selector||abi-encoded args) to EXECUTE a leaf pure/view function through a bounded stack-machine interpreter and get the returned bytes — verify an on-chain formula by execution instead of deploying to a testnet. The interpreter models stack/memory/calldata only (no storage, external calls, gas or logs); such an opcode errors rather than returning a wrong answer.",
             inputSchema={"type": "object", "properties": {
                 "source": {"type": "string", "description": "EVM bytecode as a hex string (0x-optional), or a path to a file containing hex or raw bytecode."},
                 "calldata": {"type": "string",
                              "description": "Optional hex calldata (selector||abi-args). When given, runs the runtime as a pure function and returns the output bytes instead of the tour."},
             }, "required": ["source"]}),

        Tool(name="find_dispatch_tables",
             description="Scan a PE for arrays of code pointers (a state-handler dispatch table or jump table) and validate each entry against the real function starts from the .pdata table — so it works even when a disassembler's call-graph walk is ILT-defeated. The largest table's length is typically the state/handler count of a generated state machine or VM interpreter. Returns candidate tables (section, base VA, entry count, pointer size 8=absolute-VA/4=RVA), largest first. When no strong plain table exists it hints at recover_cfg — a control-flow-flattened / MBA VM computes its successors per block (jmp rax) and has no pointer table to find.",
             inputSchema={"type": "object", "properties": {
                 "path": {"type": "string", "description": "Path to the PE file."},
             }, "required": ["path"]}),

        Tool(name="recover_cfg",
             description="Recover the real control-flow graph of a control-flow-flattened / MBA-obfuscated x86-64 function whose blocks end in a computed `jmp rax` (Flare-On-style VM obfuscation). For each block it liveness-backtracks to the 'footer expression' that computes the jump target, then emulates that footer with the whole image mapped (so its data-blob reads resolve) to read the successor — resolving conditional footers (SETZ/SETNZ/SETGE) to both edges. Returns blocks, edges, an unresolved count, and a Graphviz DOT — the edges a linear disassembler cannot see. Needs capstone + the 'emulate' extra (unicorn, pefile).",
             inputSchema={"type": "object", "properties": {
                 "path": {"type": "string", "description": "Path to the PE file."},
                 "entry": {"type": "string", "description": "Function entry address (e.g. 0x1400202b0)."},
                 "max_blocks": {"type": "integer", "default": 4000},
             }, "required": ["path", "entry"]}),

        Tool(name="symexec",
             description="Symbolic execution (angr): find the INPUT that drives the binary to a target — a win address (`find`) or a state whose stdout contains a string (`find_stdout`), while avoiding failure addresses/strings. Declare the symbolic input as `stdin_len` bytes of stdin and/or `sym_argv` (byte-lengths of symbolic argv entries). Returns the concrete stdin/argv that reaches it. Use for crackme/keygen/serial checks where pathfind (needs a recovered FSM) and emulate_function (runs one chosen path) can't discover an unknown input. Needs angr (pip install angr); bounded by timeout + state cap.",
             inputSchema={"type": "object", "properties": {
                 "path": {"type": "string", "description": "Binary to solve (defaults to the loaded analysis)."},
                 "find": {"type": "string", "description": "Win address (hex, e.g. 0x401337)."},
                 "find_stdout": {"type": "string", "description": "String the winning state must have printed (alternative to find)."},
                 "avoid": {"type": "array", "items": {"type": "string"}, "description": "Failure addresses to prune (hex)."},
                 "avoid_stdout": {"type": "string", "description": "String a failing state prints (e.g. 'Wrong')."},
                 "stdin_len": {"type": "integer", "description": "Symbolic stdin length in bytes."},
                 "sym_argv": {"type": "array", "items": {"type": "integer"}, "description": "Byte-lengths of symbolic argv entries after argv[0]."},
                 "timeout": {"type": "integer", "default": 120},
             }, "required": []}),

        Tool(name="decompile",
             description="Decompile ONE native function to C at a given address, on demand (no prior analyze needed — pass path=). Prefers r2ghidra's `pdg` (the real Ghidra decompiler, genuine C) and falls back to radare2's built-in `pdc` when r2ghidra isn't installed; `decompiler` can force pdg or pdc. Does a targeted `af` (not a full analysis) so it's fast on large binaries. For a whole loaded project's functions use get_function instead. Returns the C code + which backend produced it.",
             inputSchema={"type": "object", "properties": {
                 "address": {"type": "string", "description": "Function address (e.g. 0x401000)."},
                 "path": {"type": "string", "description": "Binary to decompile (defaults to the loaded analysis)."},
                 "decompiler": {"type": "string", "enum": ["pdg", "pdc"],
                                "description": "Force a backend (default: pdg then pdc)."},
             }, "required": ["address"]}),

        Tool(name="patch",
             description="Apply in-place byte or assembly patches to a PE / ELF / Mach-O binary and write a patched copy — NOP an anti-debug check, force a conditional jump, stub an import, or drop in new code. Each patch is either raw `bytes_hex` or `asm` source (assembled at its VA via keystone, so relative jmp/call/branch offsets are correct); `arch` defaults to the binary's own machine (x86_64/x86/arm64/arm/thumb). Also applies bundled `recipes` by name (see `chimera patch --list-recipes`). Defaults to dry_run=true — returns the before/after diff without writing; set dry_run=false (and optionally out=) to save. Assembly needs the 'patch' extra (keystone).",
             inputSchema={"type": "object", "properties": {
                 "path": {"type": "string", "description": "Binary to patch (defaults to the loaded analysis)."},
                 "patches": {"type": "array", "description": "Patches to apply.", "items": {"type": "object", "properties": {
                     "address": {"type": "string", "description": "Virtual address (hex, e.g. 0x140001234)."},
                     "asm": {"type": "string", "description": "Assembly source to encode at the VA, e.g. 'xor eax,eax; ret'."},
                     "bytes_hex": {"type": "string", "description": "Raw bytes as hex (alternative to asm)."},
                     "arch": {"type": "string", "description": "Arch for asm (default: auto from the binary)."},
                     "description": {"type": "string"},
                 }}},
                 "recipes": {"type": "array", "items": {"type": "string"}, "description": "Bundled recipe names to apply."},
                 "out": {"type": "string", "description": "Output path (default: <binary>.patched.<ext>)."},
                 "dry_run": {"type": "boolean", "default": True, "description": "Preview the diff without writing (default true)."},
             }, "required": []}),

        Tool(name="yara_scan",
             description="Scan a file (sample/dump/unpacked payload) against YARA rules on demand — the compiled-binary counterpart to run_semgrep's source patterns, for identifying family/packer/capability/IOC. Uses chimera's bundled rule set plus any rules in an optional rules_dir. Returns hits with rule name, tags, meta and matched string identifiers. Needs yara-python. (To AUTHOR a rule from findings, use the `chimera yara` CLI.)",
             inputSchema={"type": "object", "properties": {
                 "target": {"type": "string", "description": "Path to the file to scan."},
                 "rules_dir": {"type": "string", "description": "Optional directory of extra .yar/.yara rules, added to the bundled set."},
             }, "required": ["target"]}),

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

        Tool(name="find_aes_keys",
             description="Recover AES-128/192/256 keys by locating their expanded key schedule in bytes — a file (memory dump / core / any blob), a live process's memory (via /proc, writable regions), or a hex string. The schedule satisfies the AES KeyExpansion recurrence, so it is self-checking: a key computed at RUNTIME behind obfuscation (derived/decrypted/unpacked, never a literal in the binary) is still recoverable once resident. Reports each key (hex), its bit size, address/offset, and the 16 bytes after the schedule as a candidate IV (tiny-AES-c layout). Pair with a process dump or a frozen target (dynamic-analysis skill).",
             inputSchema={"type": "object", "properties": {
                 "file": {"type": "string", "description": "Path to a file/dump to scan."},
                 "pid": {"type": "integer", "description": "PID of a live process to scan (/proc)."},
                 "hex": {"type": "string", "description": "A hex byte string to scan directly."},
             }}),

        Tool(name="pathfind",
             description="Shortest labelled path through a graph/FSM edge list from a start node to an accepting node — the reusable core of 'find the input that drives this state machine to accept' (e.g. recover a password from a disassembled validator). Edges map a node to [label, next_node] transitions; the concatenated edge labels ARE the accepting input. Pure BFS, no binary needed. Use exact_length to require a path of exactly N edges (the 'N-char password' shape where shorter accepts must be rejected).",
             inputSchema={"type": "object", "properties": {
                 "edges": {"type": "object", "description": "Map of node -> list of [label, next_node] pairs."},
                 "start": {"description": "The start node."},
                 "accept": {"description": "An accepting node, or a list of accepting nodes."},
                 "exact_length": {"type": "integer", "description": "Require exactly this many edges."},
                 "max_depth": {"type": "integer", "description": "Bound the search to this many edges."},
             }, "required": ["edges", "start", "accept"]}),

        Tool(name="run_under_wine",
             description="Run a Windows PE on this Linux host under Wine as a dynamic oracle — isolated throwaway WINEPREFIX, debug output silenced. Console apps run headless (stdout captured); set xvfb for GUI apps (virtual display). A memory_scan needle is searched (ASCII + UTF-16LE) in the process memory to lift a MessageBox/window answer. Executes the binary; never raises on the common failures (wine absent, missing exe) — returns an error dict. Returns {ran, returncode, stdout, stderr, timed_out, wineprefix, memory_hits, error}.",
             inputSchema={"type": "object", "properties": {
                 "exe": {"type": "string", "description": "Path to the Windows PE to run."},
                 "args": {"type": "array", "items": {"type": "string"},
                          "description": "Command-line arguments."},
                 "xvfb": {"type": "boolean", "default": False,
                          "description": "Run under a virtual display (for GUI apps)."},
                 "timeout": {"type": "number", "default": 30,
                             "description": "Kill after N seconds."},
                 "memory_scan": {"type": "string",
                             "description": "Needle to search (ASCII+UTF-16LE) in process memory."},
                 "prefix": {"type": "string", "description": "Reuse an existing WINEPREFIX."},
             }, "required": ["exe"]}),

        Tool(name="run_sandboxed",
             description="Run a program confined by bubblewrap (no root, no daemon): isolated PID/mount/IPC/net namespaces, NETWORK OFF by default (a malware sample can't beacon), throwaway tmpfs for /tmp and $HOME, host filesystem read-only except explicit binds. Runs on the host kernel (fast; ptrace/bp-dump still work inside), unlike a VM. Use for running an untrusted crackme/sample/CTF binary. wine=true runs the target under Wine in an isolated prefix. Returns {ran, returncode, stdout, stderr, timed_out, error}.",
             inputSchema={"type": "object", "properties": {
                 "argv": {"type": "array", "items": {"type": "string"}, "description": "Program + args."},
                 "net": {"type": "boolean", "default": False, "description": "Allow network (default off)."},
                 "wine": {"type": "boolean", "default": False, "description": "Run under Wine."},
                 "ro_binds": {"type": "array", "items": {"type": "string"}, "description": "Extra read-only binds (src or src:dst)."},
                 "rw_binds": {"type": "array", "items": {"type": "string"}, "description": "Writable binds (src or src:dst)."},
                 "workdir": {"type": "string", "description": "Working directory inside the sandbox."},
                 "workspace": {"type": "string", "description": "Persistent sandbox dir bound as $HOME — repeated calls against the same workspace keep files/Wine-prefix/state, so you can drive a target step by step (free control)."},
                 "timeout": {"type": "number", "default": 30},
             }, "required": ["argv"]}),

        Tool(name="run_with_breakpoints",
             description="Launch a program (x86-64 Linux) under ptrace, break at given locations, and on each hit dump CPU registers and pointer-target memory — the no-sudo way to read a value a program computes at RUNTIME (a derived/decrypted key, an unpacked buffer) at the instant it's live. Works even under kernel.yama.ptrace_scope=1 because chimera launches (parents) the target. A breakpoint is {addr, dumps} OR {signature, delta, dumps}: 'signature' (hex bytes) is located in memory at runtime and the bp armed at found+delta — ASLR-proof (resolve a module base from a known pattern, e.g. an AES S-box). 'dumps':[[reg,len],...] reads len bytes at the address in reg. NOTE: an addr/signature not resident at the exec-stop is armed by a poller once it maps — best-effort, needs the target alive long enough to scan+arm. A Wine-hosted PE is reparented out of our tree, so under ptrace_scope=1 its memory is unreachable (needs ptrace_scope=0); native ELF works directly.",
             inputSchema={"type": "object", "properties": {
                 "argv": {"type": "array", "items": {"type": "string"},
                          "description": "Program + args to launch."},
                 "breakpoints": {"type": "array", "items": {"type": "object"},
                          "description": "[{addr:int|hex, dumps:[[reg,len]]} | {signature:hex, delta:int|hex, dumps:[[reg,len]]}]"},
                 "max_hits": {"type": "integer", "default": 1, "description": "Stop after N hits."},
                 "timeout": {"type": "number", "default": 30, "description": "Kill after N seconds."},
                 "env": {"type": "object", "description": "Extra environment for the target."},
             }, "required": ["argv", "breakpoints"]}),

        # --- Configuration ---
        Tool(name="get_config",
             description="Get or modify Chimera analysis configuration. Call with no params to read current config.",
             inputSchema={"type": "object", "properties": {
                 "set": {"type": "object", "description": "Key-value pairs to update (e.g. {\"skip_dynamic\": false, \"ghidra_max_mem\": \"8g\"})"},
             }}),
    ]
