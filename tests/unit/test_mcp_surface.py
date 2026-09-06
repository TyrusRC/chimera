"""Characterization of the MCP tool surface.

A safety net for refactoring `mcp_server`: it pins the set of tool names
and asserts every advertised tool is actually dispatchable, so a tool
cannot be silently dropped or left unreachable when handlers move
between modules. It deliberately asserts the *contract* (names, schema
shape, dispatchability), not any handler's return value.
"""
from __future__ import annotations

import asyncio

import pytest

from chimera import mcp_server


def _tools():
    return asyncio.run(mcp_server.list_tools())


def _call(name, args=None):
    return asyncio.run(mcp_server.call_tool(name, args or {}))


# Pinned deliberately: adding a tool should be a conscious update here.
EXPECTED_TOOLS = {
    "analyze", "status", "get_functions", "get_function", "get_strings",
    "get_callgraph", "get_manifest", "get_manifest_findings", "get_info",
    "get_disassembly", "detect_protections", "detect_framework",
    "detect_protocols", "detect_sdks", "get_bypass_scripts",
    "get_dynamic_hooks", "get_class_headers", "list_source_files",
    "read_source", "read_cache", "list_artifacts", "run_semgrep",
    "diff_projects", "objc_xref", "list_devices", "list_packages",
    "pull_app", "start_frida_server", "frida_attach", "frida_spawn",
    "frida_detach", "frida_exec", "frida_load_script", "frida_messages",
    "get_logcat", "setup_proxy", "clear_proxy", "get_config",
    "start_fuzz", "fuzz_status", "dotnet_trace",
    "rename_function", "set_comment", "set_function_type",
    "set_classification", "add_note", "list_annotations", "batch_annotate",
    "emulate_function",
    "detect_gpu",
}


def test_every_expected_tool_is_advertised():
    names = {t.name for t in _tools()}
    missing = EXPECTED_TOOLS - names
    assert not missing, f"tools disappeared from list_tools: {sorted(missing)}"


def test_no_unexpected_tools_appeared():
    names = {t.name for t in _tools()}
    extra = names - EXPECTED_TOOLS
    assert not extra, (
        f"new tools not pinned in this test: {sorted(extra)} — "
        "add them to EXPECTED_TOOLS deliberately"
    )


def test_tool_schemas_are_well_formed():
    for t in _tools():
        assert t.description, f"{t.name} has no description"
        assert isinstance(t.inputSchema, dict), f"{t.name} schema not a dict"
        assert t.inputSchema.get("type") == "object", f"{t.name} schema type"


def test_no_duplicate_tool_names():
    names = [t.name for t in _tools()]
    assert len(names) == len(set(names)), "duplicate tool names advertised"


_DUMMY_BY_TYPE = {
    "string": "x", "integer": 1, "number": 1, "boolean": False,
    "array": [], "object": {},
}


def _minimal_args(tool):
    """Synthesize just the arguments the tool's own schema marks required.

    The MCP framework validates arguments against `inputSchema` before a
    handler ever runs, so calling `call_tool` directly with `{}` would
    exercise a path the protocol never reaches. Supplying the required
    keys puts the handler under the same preconditions it has in
    production.
    """
    schema = tool.inputSchema or {}
    props = schema.get("properties") or {}
    args = {}
    for key in schema.get("required") or []:
        spec = props.get(key) or {}
        args[key] = _DUMMY_BY_TYPE.get(spec.get("type"), "x")
    return args


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_every_advertised_tool_is_dispatchable(name):
    """No tool may fall through to the unknown-tool branch.

    Handlers get only their required arguments, so most return a "no
    binary loaded" or device error — that is fine and expected. What must
    never happen is the catch-all "Unknown tool" reply, which is what a
    lost or mis-wired handler produces.
    """
    tool = next(t for t in _tools() if t.name == name)
    try:
        result = _call(name, _minimal_args(tool))
    except Exception:
        # Reaching the handler at all is what this asserts. Dummy arguments
        # point at nothing real, so a handler may raise (bad path, absent
        # adb device); the MCP framework turns that into isError=True and
        # the server stays up — verified against a live stdio session.
        return
    assert result, f"{name} returned nothing"
    text = "".join(getattr(c, "text", "") for c in result)
    assert "Unknown tool" not in text, f"{name} is advertised but not dispatched"


def test_an_unknown_tool_still_reports_unknown():
    """The guard itself must work, or the test above proves nothing."""
    text = "".join(getattr(c, "text", "") for c in _call("definitely_not_a_tool"))
    assert "Unknown tool" in text


def test_mcp_command_does_not_write_to_stdout():
    """stdout IS the JSONRPC transport for a stdio MCP server.

    Anything else written there corrupts the stream — a real client
    reported "Failed to parse JSONRPC message from server" on connect
    because the startup banner went to stdout.
    """
    import inspect
    from chimera.cli import serve_cmd

    # `mcp` is a click Command; the function is on `.callback`.
    src = inspect.getsource(serve_cmd.mcp.callback)
    for line in src.splitlines():
        if "click.echo" in line:
            assert "err=True" in line, (
                f"MCP startup writes to stdout, corrupting JSONRPC: {line.strip()}"
            )
