import asyncio

from chimera.mcp_handlers.analysis import dispatch


def _call(name, args):
    r = asyncio.run(dispatch(name, args))
    return r[0].text if isinstance(r, list) else str(r)


def test_centurion_tools_dispatches():
    out = _call("centurion_tools", {})
    assert "Unknown tool" not in out and "centurion" in out.lower()


def test_mantis_audit_missing_path():
    out = _call("mantis_audit", {"path": "/nonexistent/xyz-123"})
    assert "Unknown tool" not in out
    assert "not found" in out.lower() or "mantis" in out.lower()
