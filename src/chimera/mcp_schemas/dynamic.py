"""MCP tool schemas: dynamic execution: fuzzing, .NET trace, emulation, wine/sandbox/qemu, breakpoints, x64dbg."""
from __future__ import annotations

from mcp.types import Tool


def tools() -> list[Tool]:
    return [
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

        # These persist the driving model's findings into the per-binary
        # overlay.json (atomic) and update the live model. Read them back
        # with get_function / list_annotations. This is the only write path
        # in the MCP surface — everything else is read-only.
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
        Tool(name="native_oracle",
             description="Run a self-contained function FROM a target binary at NATIVE speed as an oracle — for a brute/oracle loop that emulate_function (unicorn, ~ms/call) is far too slow for, e.g. a 2^32 key/serial search over a tweaked-crypto routine (FLARE-On 13 ToxicMiner: flag=RC4(customSHA256d(diskSerial‖const)[:16], ct); ~180 ns/call → 2^32 in ~80s on 10 cores). It auto-derives the binary's loadable segments (PE sections / ELF PT_LOAD, non-PIE), maps them at their real VAs (MAP_FIXED), and runs your C `body` against them; the body reaches the target by absolute VA through a WIN64/SYSV typedef, e.g. `typedef void (WIN64 *f)(uint32_t,uint32_t,void*); ((f)0x140134ca0)(...)`, and prints findings to stdout (`IMG`=mapped base, `CHIMERA_BASE`=image base are in scope). Compiled with gcc and run CONFINED under bubblewrap (network off) because it executes untrusted native code — needs gcc+bwrap. Use `cflags` (e.g. ['-O3','-fopenmp']) and `preamble` (file-scope C: tables, helpers). Returns {available, compiled, ran, returncode, stdout, stderr, image_base, span, nsegments, source, error}. Reimplementing a tweaked algorithm by hand is error-prone; running the real bytes is exact — cross-check one input against emulate_function.",
             inputSchema={"type": "object", "properties": {
                 "binary": {"type": "string", "description": "Path to the target PE/ELF (bound read-only into the sandbox)."},
                 "body": {"type": "string", "description": "C inserted into main() after the image loads; calls target VAs and prints to stdout."},
                 "preamble": {"type": "string", "description": "File-scope C (typedefs, tables, helper functions)."},
                 "cflags": {"type": "array", "items": {"type": "string"}, "description": "gcc flags (default ['-O2']); add '-fopenmp' for a parallel brute."},
                 "timeout": {"type": "number", "default": 300, "description": "Kill the run after N seconds."},
                 "confine": {"type": "boolean", "default": True, "description": "Run under bwrap (default). false runs UNCONFINED — only for code you trust."},
                 "net": {"type": "boolean", "default": False, "description": "Allow network in the sandbox (default off)."},
             }, "required": ["binary", "body"]}),
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
        Tool(name="qemu_boot",
             description="Boot a firmware/disk image under QEMU headless and capture its console — the firmware analogue of run_under_wine/hdl_sim, and the runtime companion to fw_extract (which only carves statically). Some answers appear ONLY at runtime: a boot-stage ransomware's note, a flag a bootkit prints, the behaviour of a malicious DXE. Pass `bios` (e.g. an OVMF image) and/or `disk` (raw image, mounted copy-on-write); drive an interactive EFI/DOS shell by giving `input_lines` (typed over serial after boot, one per line_delay). Confined: no network by default, disk copy-on-write (image never modified), -no-reboot, hard timeout. Returns the captured (ANSI-stripped) console text. Needs qemu-system-x86_64.",
             inputSchema={"type": "object", "properties": {
                 "bios": {"type": "string", "description": "Firmware image path (OVMF/BIOS)."},
                 "disk": {"type": "string", "description": "Raw disk image path (mounted copy-on-write)."},
                 "input_lines": {"type": "array", "items": {"type": "string"}, "description": "Console lines to type into the guest after boot (drive an EFI/DOS shell)."},
                 "boot_wait": {"type": "number", "default": 8.0, "description": "Seconds to wait before the first input."},
                 "line_delay": {"type": "number", "default": 1.5, "description": "Seconds between input lines."},
                 "timeout": {"type": "integer", "default": 90},
                 "net": {"type": "boolean", "default": False, "description": "Allow guest networking (default off)."},
             }, "required": []}),
        Tool(name="hdl_sim",
             description="Compile a Verilog/SystemVerilog design with Icarus Verilog and run it under vvp, capturing the testbench's $display output — the HDL analogue of run_under_wine, for a 'reverse this hardware core' target where the answer is produced by SIMULATING the design (chimera otherwise has no HDL path). Pass `sources` (the .v files) and the `top` module to elaborate; edit a testbench first if you need to drive a specific input. iverilog/vvp are external: on PATH (apt install iverilog) or passed explicitly via iverilog=/vvp= (a rootless dpkg-deb -x extract works — add its ivl backend with flags=['-g2012','-B','<dir>']). Returns {available, compiled, returncode, stdout, stderr}; binary output is decoded leniently.",
             inputSchema={"type": "object", "properties": {
                 "sources": {"type": "array", "items": {"type": "string"}, "description": "Verilog source file paths (design + testbench)."},
                 "top": {"type": "string", "description": "Top module to elaborate (iverilog -s)."},
                 "flags": {"type": "array", "items": {"type": "string"}, "description": "iverilog flags (default ['-g2012'])."},
                 "vvp_flags": {"type": "array", "items": {"type": "string"}, "description": "Extra vvp flags."},
                 "iverilog": {"type": "string", "description": "iverilog path (default: PATH)."},
                 "vvp": {"type": "string", "description": "vvp path (default: PATH)."},
                 "timeout": {"type": "integer", "default": 120},
             }, "required": ["sources"]}),
        Tool(name="x64dbg",
             description=(
                 "Drive a REAL x64dbg debugger on a Windows host over the x64dbgmcp "
                 "plugin's HTTP API — full live control (registers, memory, breakpoints, "
                 "single-step, assemble, patch, module/thread/callstack inspection) as a "
                 "chimera tool. Use this when a target can't be driven by chimera's in-host "
                 "oracles (emulate_function/run_under_wine/run_with_breakpoints): an "
                 "aggressively anti-analysis Windows PE that fast-fails/self-modifies, or a "
                 "value that only exists once the process is live on real Windows. Prereq: "
                 "x64dbg running on the Windows box with the MCP plugin loaded (serves "
                 "127.0.0.1:8888; on WSL2 mirrored networking that loopback is shared, so the "
                 "default URL works — otherwise set url= or CHIMERA_X64DBG_URL). Addresses are "
                 "hex strings ('0x140001070') or x64dbg expressions, in the TARGET's address "
                 "space. Typical loop: exec (cmd='init C:\\\\path\\\\t.exe') -> bp_set "
                 "(addr=...) -> run -> regs / mem_read -> stepin. Actions: exec{cmd,offset?,"
                 "limit?}, is_debugging, is_active, run, pause, stop, stepin, stepover, "
                 "stepout, step_disasm; bp_set{addr}, bp_del{addr}, bp_list{type?}, "
                 "hwbp_set{addr,type?}, hwbp_del{addr}; reg_get{register}, reg_set{register,"
                 "value}, regs, flag_get{flag}, flag_set{flag,value}; mem_read{addr,size}, "
                 "mem_write{addr,data}, mem_valid{addr}, mem_protect{addr}, mem_base{addr}, "
                 "mem_map, mem_alloc{size,addr?}, mem_free{addr}, set_page_rights{addr,rights}; "
                 "disasm{addr,count?}, assemble{addr,instruction}, assemble_mem{addr,"
                 "instruction}, patch_list, patch_get{addr}; modules, symbols{module,offset?,"
                 "limit?}, threads, teb{tid}, callstack, string_at{addr}, xref_get{addr}, "
                 "xref_count{addr}, branch_dest{addr}, parse_expr{expression}, "
                 "getprocaddr{module,api}, pattern_find{start,size,pattern}, tcp_conns, "
                 "handles; stack_pop, stack_push{value}, stack_peek{offset?}; label_set{addr,"
                 "text}, label_get{addr}, label_list, comment_set{addr,text}, comment_get{addr}. "
                 "'raw'{endpoint,method?} reaches any endpoint not named here. Never raises: a "
                 "plugin that's down returns an error dict."),
             inputSchema={"type": "object", "properties": {
                 "action": {"type": "string",
                            "description": "Operation name (see description), or 'raw'."},
                 "params": {"type": "object",
                            "description": "Endpoint params, forwarded verbatim as the query string (e.g. {\"addr\":\"0x140001070\",\"size\":\"32\"})."},
                 "endpoint": {"type": "string",
                              "description": "For action='raw': the plugin endpoint path (e.g. 'Memory/Read')."},
                 "method": {"type": "string",
                            "description": "For action='raw': HTTP method (default GET)."},
                 "url": {"type": "string",
                         "description": "Override the plugin base URL (default env CHIMERA_X64DBG_URL or http://127.0.0.1:8888/)."},
                 "timeout": {"type": "number", "default": 10,
                             "description": "Per-call HTTP timeout in seconds."},
             }, "required": ["action"]}),
    ]
