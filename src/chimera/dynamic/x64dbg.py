"""Live x64dbg control channel — drive a real Windows debugger from chimera.

chimera's other dynamic oracles run the target *here* (Wine, unicorn, QEMU,
ptrace). Some targets can't be driven that way: an aggressively anti-analysis
Windows PE that fast-fails under Wine, self-modifies, or only reveals a value
once it's live on real Windows. For those, the analyst runs the target in
x64dbg on a Windows box with the x64dbgmcp plugin (an HTTP server the plugin
exposes, default 127.0.0.1:8888), and chimera speaks to that HTTP API — so the
full debugger (registers, memory, breakpoints, single-step, assemble, patch)
becomes a chimera tool instead of a second, disconnected MCP server.

Reachability: on WSL2 with mirrored networking the Windows loopback IS the
Linux loopback, so the default localhost URL just works; otherwise point
`url=` / `CHIMERA_X64DBG_URL` at the Windows host.

Transport matches the plugin: every call is an HTTP GET with query params
(the plugin models even writes as GETs), except Memory/SetPageRights which is
a POST. Responses are JSON when the plugin emits it, otherwise raw text. This
never raises on a transport failure (plugin not running, host unreachable) —
it returns an ``{"ok": False, "error": ...}`` dict so a handler degrades to a
clear message instead of a traceback.

Uses stdlib urllib (as eth_rpc does) — no new dependency for a handful of
localhost GETs.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_URL = "http://127.0.0.1:8888/"

#: action → (HTTP method, plugin endpoint). This is the whole x64dbgmcp plugin
#: surface, given stable chimera-side names. Any params supplied by the caller
#: are forwarded verbatim as the query string, so the required params live in
#: the tool description, not here. The `raw` escape hatch (handled separately)
#: reaches any endpoint this table doesn't name yet — so a newer plugin build
#: is controllable without a chimera change.
ACTIONS: dict[str, tuple[str, str]] = {
    # session / flow control
    "exec": ("GET", "ExecCommand"),           # run ANY x64dbg command (init, bp, go, ...)
    "is_debugging": ("GET", "Is_Debugging"),
    "is_active": ("GET", "IsDebugActive"),
    "run": ("GET", "Debug/Run"),
    "pause": ("GET", "Debug/Pause"),
    "stop": ("GET", "Debug/Stop"),
    "stepin": ("GET", "Debug/StepIn"),
    "stepover": ("GET", "Debug/StepOver"),
    "stepout": ("GET", "Debug/StepOut"),
    "step_disasm": ("GET", "Disasm/StepInWithDisasm"),
    # breakpoints
    "bp_set": ("GET", "Debug/SetBreakpoint"),
    "bp_del": ("GET", "Debug/DeleteBreakpoint"),
    "bp_list": ("GET", "Breakpoint/List"),
    "hwbp_set": ("GET", "Debug/SetHardwareBreakpoint"),
    "hwbp_del": ("GET", "Debug/DeleteHardwareBreakpoint"),
    # registers / flags
    "reg_get": ("GET", "Register/Get"),
    "reg_set": ("GET", "Register/Set"),
    "regs": ("GET", "RegisterDump"),
    "flag_get": ("GET", "Flag/Get"),
    "flag_set": ("GET", "Flag/Set"),
    # memory
    "mem_read": ("GET", "Memory/Read"),
    "mem_write": ("GET", "Memory/Write"),
    "mem_valid": ("GET", "Memory/IsValidPtr"),
    "mem_protect": ("GET", "Memory/GetProtect"),
    "mem_base": ("GET", "MemoryBase"),
    "mem_map": ("GET", "MemoryMap"),
    "mem_alloc": ("GET", "Memory/RemoteAlloc"),
    "mem_free": ("GET", "Memory/RemoteFree"),
    "set_page_rights": ("POST", "Memory/SetPageRights"),
    # disassembly / assembly / patching
    "disasm": ("GET", "Disasm/GetInstructionRange"),
    "assemble": ("GET", "Assembler/Assemble"),
    "assemble_mem": ("GET", "Assembler/AssembleMem"),
    "patch_list": ("GET", "Patch/List"),
    "patch_get": ("GET", "Patch/Get"),
    # inspection
    "modules": ("GET", "GetModuleList"),
    "symbols": ("GET", "SymbolEnum"),
    "threads": ("GET", "GetThreadList"),
    "teb": ("GET", "GetTebAddress"),
    "callstack": ("GET", "GetCallStack"),
    "string_at": ("GET", "String/GetAt"),
    "xref_get": ("GET", "Xref/Get"),
    "xref_count": ("GET", "Xref/Count"),
    "branch_dest": ("GET", "GetBranchDestination"),
    "parse_expr": ("GET", "Misc/ParseExpression"),
    "getprocaddr": ("GET", "Misc/RemoteGetProcAddress"),
    "pattern_find": ("GET", "Pattern/FindMem"),
    "tcp_conns": ("GET", "EnumTcpConnections"),
    "handles": ("GET", "EnumHandles"),
    # stack
    "stack_pop": ("GET", "Stack/Pop"),
    "stack_push": ("GET", "Stack/Push"),
    "stack_peek": ("GET", "Stack/Peek"),
    # labels / comments (persist analysis into the x64dbg db)
    "label_set": ("GET", "Label/Set"),
    "label_get": ("GET", "Label/Get"),
    "label_list": ("GET", "Label/List"),
    "comment_set": ("GET", "Comment/Set"),
    "comment_get": ("GET", "Comment/Get"),
}


def _resolve_url(url: str | None) -> str:
    base = url or os.environ.get("CHIMERA_X64DBG_URL") or DEFAULT_URL
    return base if base.endswith("/") else base + "/"


def _decode_body(raw: bytes) -> object:
    text = raw.decode("utf-8", "replace")
    try:
        return json.loads(text)
    except (ValueError, json.JSONDecodeError):
        return text


def x64dbg_call(
    action: str,
    params: dict | None = None,
    *,
    endpoint: str | None = None,
    method: str | None = None,
    url: str | None = None,
    timeout: float = 10.0,
) -> dict:
    """Invoke one x64dbg plugin endpoint. Never raises on a transport error.

    `action` is a name from ACTIONS, or "raw" to hit an arbitrary `endpoint`
    (with an optional `method`, default GET). `params` are forwarded verbatim
    as the query string (or POST body for set_page_rights). Address/size values
    are whatever the plugin expects — hex strings like "0x140001070" or an
    x64dbg expression, so the caller stays in the target's own address space.
    """
    params = {k: v for k, v in (params or {}).items() if v is not None}

    if action == "raw":
        if not endpoint:
            return {"ok": False, "error": "raw action needs endpoint=..."}
        ep, meth = endpoint, (method or "GET").upper()
    else:
        spec = ACTIONS.get(action)
        if spec is None:
            return {"ok": False, "action": action,
                    "error": f"unknown action '{action}'. "
                             f"Known: {', '.join(sorted(ACTIONS))}, raw."}
        meth, ep = spec[0], spec[1]

    base = _resolve_url(url)
    full = base + ep.lstrip("/")
    qs = urllib.parse.urlencode({k: str(v) for k, v in params.items()})

    try:
        if meth == "POST":
            body = qs.encode("utf-8")
            req = urllib.request.Request(
                full, data=body, method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"})
        else:
            req = urllib.request.Request(
                full + (f"?{qs}" if qs else ""), method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - localhost debugger plugin
            status = resp.status
            data = _decode_body(resp.read())
    except urllib.error.HTTPError as exc:
        return {"ok": False, "action": action, "endpoint": ep,
                "status": exc.code, "error": f"HTTP {exc.code}: {exc.reason}"}
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        return {"ok": False, "action": action, "endpoint": ep,
                "error": f"cannot reach x64dbg plugin at {base} "
                         f"(is x64dbg running with the MCP plugin loaded?): {exc}"}

    out: dict = {"ok": True, "action": action, "endpoint": ep, "status": status}
    if isinstance(data, dict):
        out["result"] = data
    elif isinstance(data, str):
        out["text"] = data
    else:
        out["result"] = data
    return out


def ping(url: str | None = None, timeout: float = 5.0) -> dict:
    """Cheap reachability + state probe: is the plugin up, is a target loaded."""
    return x64dbg_call("is_debugging", url=url, timeout=timeout)
