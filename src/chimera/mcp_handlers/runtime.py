"""Dynamic execution: fuzzing, .NET runtime tracing, and server config.

Returns None when the tool is not one of this module's, so the server can
try the next handler group.
"""
from __future__ import annotations

import logging
from pathlib import Path

from mcp.types import TextContent

from chimera import mcp_session as mcpstate

logger = logging.getLogger(__name__)


async def dispatch(name: str, arguments: dict) -> list[TextContent] | None:
    engine = mcpstate.get_engine()
    if name == "start_fuzz":
        afl = engine.registry.get("afl++")
        if not afl or not afl.is_available():
            return mcpstate.error("AFL++ (afl-fuzz) is not installed.")
        result = await afl.analyze(arguments["binary"], {
            "input_dir": arguments["input_dir"],
            "output_dir": arguments["output_dir"],
            "duration": arguments.get("duration", 300),
            "qemu": arguments.get("qemu", True),
        })
        return mcpstate.json_reply(result)

    # ── fuzz_status ─────────────────────────────────────────────────────
    if name == "fuzz_status":
        afl = engine.registry.get("afl++")
        if not afl or not afl.is_available():
            return mcpstate.error("AFL++ not installed.")
        result = await afl.get_campaign_status(arguments["campaign_id"])
        return mcpstate.json_reply(result)

    # ── get_config ──────────────────────────────────────────────────────
    if name == "get_config":
        updates = arguments.get("set")
        if updates:
            config = engine.config
            allowed = {"skip_dynamic", "skip_fuzzing", "ghidra_max_mem", "adb_device", "ios_udid", "ghidra_home"}
            applied = {}
            for k, v in updates.items():
                if k in allowed and hasattr(config, k):
                    setattr(config, k, v)
                    applied[k] = v
            return mcpstate.json_reply({"updated": applied})
        # Read config
        config = engine.config
        return mcpstate.json_reply({
            "project_dir": str(config.project_dir),
            "cache_dir": str(config.cache_dir),
            "ghidra_home": config.ghidra_home,
            "ghidra_max_mem": config.ghidra_max_mem,
            "skip_dynamic": config.skip_dynamic,
            "skip_fuzzing": config.skip_fuzzing,
            "adb_device": config.adb_device,
            "ios_udid": config.ios_udid,
        })

    # ── dotnet_trace ────────────────────────────────────────────────────
    if name == "dotnet_trace":
        import tempfile
        from chimera.dotnet.tracer import trace, dotnet_available

        path = arguments["path"]
        if not Path(path).exists():
            return mcpstate.error(f"file not found: {path}")
        if not dotnet_available():
            return mcpstate.error(
                "the .NET SDK is not installed — `dotnet` not found on PATH.")

        methods = arguments.get("methods") or []
        inputs = arguments.get("inputs") or []
        wd = Path(tempfile.mkdtemp(prefix="chimera_dotnet_mcp_"))
        result = trace(
            Path(path), list(methods),
            stdin_lines=list(inputs) if inputs else None,
            neutralize_pinvoke=arguments.get("neutralize_pinvoke", True),
            work_dir=wd, timeout=int(arguments.get("timeout", 120)),
        )
        if not result.available:
            return mcpstate.error(result.error or "tracer unavailable")

        streams = {
            method: {
                chan: {
                    "ascii": result.reconstruct_ascii(vals),
                    "ints": vals,
                }
                for chan, vals in chans.items() if vals
            }
            for method, chans in result.numeric_streams().items()
        }
        return mcpstate.json_reply({
            "traced": Path(path).name,
            "hooks_installed": result.hooks_installed,
            "inputs": list(inputs),
            "note": result.error,
            "byte_values": [
                {"method": m, "ascii": a, "hex": h}
                for m, a, h in result.byte_values()
            ],
            "strings": [{"method": m, "value": v} for m, v in result.strings_seen()],
            "numeric_streams": streams,
        })

    # ── emulate_function ────────────────────────────────────────────────
    if name == "emulate_function":
        from chimera.dynamic.emulate import emulate_function, unicorn_available
        if not unicorn_available():
            return mcpstate.error(
                'unicorn not installed — pip install "chimera[emulate]"')
        if not mcpstate.require_model():
            return mcpstate.error("No analysis loaded. Call analyze(path=...) first.")
        model = mcpstate.current_model
        path = mcpstate.analysis_config.get("path") or str(model.binary.path)
        arch = arguments.get("arch") or model.binary.arch.value
        if arch.startswith("arm64"):
            arch = "arm64"          # arm64e emulates as arm64
        try:
            args = tuple(int(a) for a in (arguments.get("args") or []))
        except (TypeError, ValueError):
            return mcpstate.error("'args' must be a list of integers.")
        read_back = []
        for r in (arguments.get("read_back") or []):
            addr = r.get("address")
            addr = int(addr, 16) if isinstance(addr, str) else int(addr)
            read_back.append((addr, int(r.get("length", 16))))
        result = emulate_function(
            path, arguments["address"], arch=arch, args=args,
            read_back=tuple(read_back),
            max_insns=int(arguments.get("max_insns", 200_000)))
        return mcpstate.json_reply(result)

    if name == "run_under_wine":
        from chimera.dynamic.wine import run_under_wine

        exe = arguments["exe"]
        if not Path(exe).exists():
            return mcpstate.error(f"file not found: {exe}")
        result = run_under_wine(
            exe,
            arguments.get("args") or (),
            prefix=arguments.get("prefix"),
            headless=not arguments.get("xvfb", False),
            xvfb=bool(arguments.get("xvfb", False)),
            timeout=float(arguments.get("timeout", 30)),
            memory_scan=arguments.get("memory_scan"),
        )
        return mcpstate.json_reply(result)

    if name == "run_with_breakpoints":
        from chimera.dynamic.ptrace_bp import PtraceUnsupported, run_with_breakpoints

        argv = arguments.get("argv") or []
        if not argv:
            return mcpstate.error("run_with_breakpoints needs a non-empty argv")
        bps = []
        for b in arguments.get("breakpoints") or []:
            spec = {"dumps": b.get("dumps") or []}
            if "signature" in b:
                spec["signature"] = b["signature"]
                d = b.get("delta", 0)
                spec["delta"] = int(d, 0) if isinstance(d, str) else int(d)
            else:
                addr = b["addr"]
                spec["addr"] = int(addr, 16) if isinstance(addr, str) else int(addr)
            bps.append(spec)
        try:
            result = run_with_breakpoints(
                [str(a) for a in argv], bps,
                env=arguments.get("env"),
                timeout=float(arguments.get("timeout", 30)),
                max_hits=int(arguments.get("max_hits", 1)),
            )
        except PtraceUnsupported as exc:
            return mcpstate.error(str(exc))
        # hex-encode register ints for a clean JSON payload
        for h in result.get("hits", []):
            h["registers"] = {k: hex(v) for k, v in h.get("registers", {}).items()}
        return mcpstate.json_reply(result)

    return None
