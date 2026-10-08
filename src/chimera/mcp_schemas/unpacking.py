"""MCP tool schemas: static unpackers / code extractors (frozen apps, bundles, archives)."""
from __future__ import annotations

from mcp.types import Tool


def tools() -> list[Tool]:
    return [
        Tool(name="py_unwrap",
             description="Recursively peel marshal/zlib/base64/base85/bz2/lzma layers from a .py/.pyc/blob and dump the version-independent co_names/co_consts tree for every code object found; read-only, never executes the target. Use for obfuscated/packed Python — a .py that exec()s a marshalled/compressed/encoded blob, or nested-encoded bytecode. Set disasm to also disassemble each recovered code node (uses xdis for cross-version when installed).",
             inputSchema={"type": "object", "properties": {
                 "path": {"type": "string", "description": "Path to the .py / .pyc / blob file."},
                 "disasm": {"type": "boolean", "default": False,
                            "description": "Also disassemble each recovered code node."},
             }, "required": ["path"]}),
        Tool(name="fw_extract",
             description="Carve a UEFI firmware image (OVMF/BIOS/SPI flash) into its modules — chimera otherwise has NO firmware concept (analyze mis-sniffs a firmware volume as ELF and aborts). Recurses the firmware volumes and returns one entry per FFS file carrying a PE32/TE image: its GUID, UI-name (e.g. 'Shell', 'BdsDxe'), kind and size — the way to spot a bootkit/implant or a CTF's malicious DXE among the stock modules. Pass extract_dir to write each module out as a normal .efi PE for further analysis (decompile/emulate it). Needs the 'firmware' extra (uefi_firmware).",
             inputSchema={"type": "object", "properties": {
                 "path": {"type": "string", "description": "Path to the firmware image (bios.bin / OVMF / flash dump)."},
                 "extract_dir": {"type": "string", "description": "Directory to extract the PE/TE modules into."},
             }, "required": ["path"]}),
        Tool(name="node_extract",
             description="Recover the embedded JavaScript from a Node.js compiled executable — a whole Node app shipped as one native binary (a large `.exe`/ELF that just 'asks for a flag') by nexe, Node SEA (Single Executable Applications), or vercel/pkg. The JS bundle is appended (nexe: `<nexe~~sentinel>` + a float64 size footer) or injected as a resource/section (SEA: a `NODE_SEA_BLOB` with magic 0x143DB6DE, uint32 flags, size-prefixed main script); running `analyze` on such a file wastes a full Ghidra pass on the node runtime and never reaches the app logic. This carves the JS back out (format-agnostic byte scan — PE/ELF/Mach-O), inflating a gzip'd nexe bundle, and writes it to disk so you can hand it straight to js_deobf. nexe and SEA are extracted; a pkg binary is detected with guidance (its virtual-filesystem payload may be V8 bytecode, target-specific). Also unpacks an Electron `app.asar` archive (the JSON-header + concatenated-bodies bundle holding a desktop app's real JS/HTML/assets) — point it at the app.asar under `resources/`, not the Electron launcher .exe. Read-only; never executes the target.",
             inputSchema={"type": "object", "properties": {
                 "path": {"type": "string", "description": "Path to the compiled Node binary (PE/ELF/Mach-O) or an Electron app.asar."},
                 "out_dir": {"type": "string", "description": "Output directory (default: <name>_node beside the input)."},
             }, "required": ["path"]}),
        Tool(name="tauri_extract",
             description="Carve the embedded web frontend out of a Tauri (Rust desktop app) binary — the analogue of node_extract/dotnet_extract for Tauri's packaging. Tauri compiles its UI (HTML/JS/CSS/images) INTO the Rust executable via EmbeddedAssets; on an ELF build that's a table in `.data.rel.ro` of 32-byte `[key_ptr,key_len,blob_ptr,blob_len]` entries whose pointers are R_X86_64_RELATIVE relocations and whose blobs are usually brotli-compressed. This finds that table with NO hardcoded offsets (scans the relocated data section for the entry shape), resolves the relocs, decompresses each asset (brotli→zstd→stored), and writes them to disk — plus it fingerprints the Tauri version and whether the app statically links its own V8 (rusty_v8). CRUCIAL caveat it flags: some Tauri apps DON'T ship their real logic in these static assets — they embed a V8 isolate and runtime-decrypt the script; when index.html references a script that isn't among the carved assets, or rusty_v8 is linked, the carved frontend is only a shell and the logic must be recovered dynamically. ELF carving is implemented; PE/Mach-O Tauri is detected (version + V8) but not yet carved. Read-only; never executes the target. Hand recovered .js/.html to js_deobf.",
             inputSchema={"type": "object", "properties": {
                 "path": {"type": "string", "description": "Path to the Tauri executable (ELF carved; PE/Mach-O detected only)."},
                 "out_dir": {"type": "string", "description": "Output directory (default: <name>_tauri_assets beside the input)."},
             }, "required": ["path"]}),
        Tool(name="flutter_extract",
             description="Extract the Dart classes/methods from a Flutter (Dart AOT) app via B(l)utter — the static RE path for a Flutter APK/bundle whose logic is compiled into libapp.so (not readable as Java/Kotlin or plain native). PATH is an unpacked APK dir, an APK file, or a libapp.so / App binary directly; auto-detects libapp from a dir. Writes recovered Dart class/method sources + an IDA/radare2 import script. Needs the `blutter` binary (github.com/worawit/blutter on PATH or CHIMERA_BLUTTER_BIN). For traffic MITM / offset dumping use flutter_patch instead.",
             inputSchema={"type": "object", "properties": {
                 "path": {"type": "string", "description": "Unpacked APK dir, APK file, or libapp.so / App binary."},
                 "out_dir": {"type": "string", "description": "Output dir (default: <name>_blutter beside the input)."},
                 "libapp": {"type": "string", "description": "Explicit libapp.so / App binary (skips auto-detect)."},
                 "blutter_bin": {"type": "string", "description": "Path to the blutter binary (default: PATH / CHIMERA_BLUTTER_BIN)."},
             }, "required": ["path"]}),
        Tool(name="flutter_patch",
             description="Repackage a Flutter APK for dynamic analysis via reFlutter — the dynamic complement to flutter_extract. Flutter apps ignore the system proxy and bundle their own CA, so normal MITM fails; `traffic` mode patches the engine to route HTTP(S) through your proxy with pinning disabled, and `offset` mode dumps absolute Dart code offsets (dump.dart) at runtime. Produces a release.RE.apk to install and drive. Needs `reflutter` (pip install reflutter) and network to fetch the matching patched engine.",
             inputSchema={"type": "object", "properties": {
                 "apk": {"type": "string", "description": "Path to the Flutter APK."},
                 "out_dir": {"type": "string", "description": "Output dir for the patched release.RE.apk."},
                 "mode": {"type": "string", "enum": ["traffic", "offset"], "default": "traffic", "description": "traffic: proxy + pinning off; offset: dump Dart offsets."},
                 "proxy_ip": {"type": "string", "description": "Proxy (Burp/mitmproxy) IP (required for traffic mode)."},
                 "reflutter_bin": {"type": "string", "description": "Path to the reflutter binary (default: PATH / CHIMERA_REFLUTTER_BIN)."},
             }, "required": ["apk", "out_dir"]}),
        Tool(name="hermes_decompile",
             description="Decompile a React Native Hermes bytecode bundle (HBC) via hermes-decomp — the RE path for a React Native app whose JS ships as Hermes bytecode, not plain/minified JS (so js_deobf/webcrack don't apply). PATH is a raw .hbc, an APK's index.android.bundle, an IPA's main.jsbundle, or a dir to auto-detect. Recovers control flow + closures (HBC v40–99). Needs the `hermes-decomp` binary (github.com/SymbioticSec/hermes-decomp on PATH or CHIMERA_HERMES_DECOMP_BIN).",
             inputSchema={"type": "object", "properties": {
                 "path": {"type": "string", "description": ".hbc / index.android.bundle / main.jsbundle, or a dir to auto-detect."},
                 "out_dir": {"type": "string", "description": "Output directory (default: alongside input)."},
                 "hermes_bin": {"type": "string", "description": "Path to hermes-decomp (default: PATH / CHIMERA_HERMES_DECOMP_BIN)."},
                 "timeout": {"type": "integer", "default": 300, "description": "Subprocess timeout (seconds)."},
             }, "required": ["path"]}),
        Tool(name="sourcemap",
             description="Recover the original source tree from a JavaScript bundle or a .map file — the web-RE path when a minified/bundled app ships (or references via sourceMappingURL) a source map with embedded original content. PATH is a .map or a bundle; writes each recovered original source to disk. Complements js_deobf (which deobfuscates when there is NO source map). Pure-Python, no external tool.",
             inputSchema={"type": "object", "properties": {
                 "path": {"type": "string", "description": "A .map file, or a JS bundle with a sourceMappingURL."},
                 "out_dir": {"type": "string", "description": "Output dir for recovered sources (default: <name>_src)."},
             }, "required": ["path"]}),
        Tool(name="dotnet_extract",
             description="Extract the files from a .NET single-file (self-contained) application — a `dotnet publish -p:PublishSingleFile=true` app that bundles the managed assembly, the whole CoreCLR runtime, every framework DLL and the `.deps.json`/`.runtimeconfig.json` into ONE native executable (a small apphost + the bundle appended as an overlay). On disk it's a plain PE/ELF/Mach-O, so `analyze` would hand ~100MB of CoreCLR host to Ghidra and never reach the app's managed assembly — the .NET analogue of the nexe/SEA/PyInstaller dead ends. This locates the bundle via its fixed signature, parses the Microsoft.NET.HostModel manifest, inflates any DEFLATE-compressed entries, and writes every file to disk — then points at the recovered main managed assembly (the app DLL, skipping System.*/Microsoft.* framework + satellite resources) so you can run `analyze`/ILSpy on it. Read-only; never executes the target. (The ILSpy pass auto-handles an assembly targeting a .NET newer than the installed ilspycmd.)",
             inputSchema={"type": "object", "properties": {
                 "path": {"type": "string", "description": "Path to the .NET single-file executable (PE/ELF/Mach-O)."},
                 "out_dir": {"type": "string", "description": "Output directory (default: <name>_bundle beside the input)."},
             }, "required": ["path"]}),
        Tool(name="js_deobf",
             description="Deobfuscate a standalone JavaScript / HTML file — the web counterpart to py_unwrap, for an obfuscated web CTF page or a malicious dropper's inline script (chimera otherwise only handled JS inside the React Native bundle pipeline, and `analyze` mis-sniffs HTML as a binary). Follows the web module graph from the entry — inline <script> bodies PLUS every local external <script src> and ES-imported file (import/export…from/dynamic import(); remote URLs and bare npm packages are skipped, network stays off) — runs webcrack (undo control-flow flattening, inline the string array, unminify, split modules), then line-splits the result (prettier, or a built-in splitter) so a multi-MB one-liner becomes greppable. Returns the module graph and per-file paths + byte sizes — the cleaned content is left on disk (grep/read it), not inlined. Pass `resolve=\"NAME[IDX]\"` to instead STATICALLY read one element of a `const NAME = [ … ]` array literal across the collected sources (no node needed) — the recurring \"indexed table → flag\" web-CTF pattern. Needs node + webcrack for deobfuscation (npm i -g webcrack, or via npx); --resolve works without it.",
             inputSchema={"type": "object", "properties": {
                 "path": {"type": "string", "description": "Path to the .js or .html file (entry point of the web app)."},
                 "out_dir": {"type": "string", "description": "Output directory (default: <name>_deobf beside the input)."},
                 "prettier": {"type": "boolean", "default": True, "description": "Format with prettier (else the built-in line-splitter)."},
                 "resolve": {"type": "string", "description": "Statically resolve one const-array element, e.g. \"TABLE[12]\" — returns the value without running node/webcrack."},
             }, "required": ["path"]}),
        Tool(name="zip_legacy",
             description="Extract a ZIP that stdlib `zipfile`/`unzip`/`7z` refuse — legacy **Reduce** compression (methods 2-5) and **ZipCrypto** (traditional PKWARE) encryption. Scans LOCAL file headers directly (robust to a mangled/absent central directory, as CTF ZIPs use), decrypts with `password` where needed, and decompresses stored/deflate (stdlib) or Reduce (this tool). FLARE-On 13 ch3 hid an answer in a method-2-Reduce + ZipCrypto `flag.txt` (password `infected` → `reduce_not_deflate`). Returns per entry {name, method, encrypted, usize, text/hex or error}. Shrink(1)/Implode(6) are reported, not decoded.",
             inputSchema={"type": "object", "properties": {
                 "path": {"type": "string", "description": "ZIP file (or any container holding a ZIP)."},
                 "password": {"type": "string", "description": "ZipCrypto password (if encrypted)."},
             }, "required": ["path"]}),
        Tool(name="polyglot_scan",
             description="Scan a file for EMBEDDED formats at ANY offset — the polyglot / carved-container triage a first-format parser misses (a CTF file that is PDF+ZIP+Mach-O+VHD+EICAR at once, real payload at a non-zero offset). Finds magics for PE/ELF/Mach-O (incl. fat, with its arch slices) / PDF / ZIP / gzip / 7z / PNG / RAR / VHD / ISO-UDF / EICAR, with a computed size where the format allows. Use `chimera polyglot --extract <offset>` to carve one out. Read-only.",
             inputSchema={"type": "object", "properties": {
                 "path": {"type": "string", "description": "File to scan for embedded formats."},
             }, "required": ["path"]}),
    ]
