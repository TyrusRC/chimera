import asyncio

from chimera.mcp_handlers import vm as vmh


def _call(name, args):
    return asyncio.run(vmh.dispatch(name, args))


def test_vm_list_unavailable_is_clean(monkeypatch):
    monkeypatch.setattr("chimera.mcp_handlers.vm.get_provider", lambda name=None: None)
    out = _call("vm_list", {})
    assert "available" in out[0].text and "false" in out[0].text.lower()


def test_vm_exec_requires_snapshot(monkeypatch):
    class P:
        name = "virtualbox"

        def available(self):
            return True

    monkeypatch.setattr("chimera.mcp_handlers.vm.get_provider", lambda name=None: P())
    out = _call("vm_exec", {"vm": "v", "argv": ["x"], "guest_user": "u"})
    assert "snapshot" in out[0].text.lower() and "error" in out[0].text.lower()


def test_returns_none_for_foreign_tool():
    assert _call("not_a_vm_tool", {}) is None
