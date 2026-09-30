import asyncio

from chimera.mcp_handlers import analysis


def test_ida_route_reports_unavailable(monkeypatch):
    from chimera.adapters import ida
    monkeypatch.setattr(ida.IdaAdapter, "is_available", lambda self: False)
    monkeypatch.setattr(ida.IdaAdapter, "_resolve_idat", staticmethod(lambda: None))
    out = asyncio.run(analysis.dispatch(
        "decompile", {"address": "0x1", "path": __file__, "decompiler": "ida"}))
    text = out[0].text.lower()
    assert "ida" in text and ("not found" in text or "install" in text)


def test_pdg_route_still_uses_radare2(monkeypatch):
    seen = {}
    from chimera.adapters.radare2 import Radare2Adapter

    async def fake_analyze(self, p, o):
        seen["engine"] = "r2"
        seen["opts"] = o
        return {"ok": True, "backend": "r2ghidra", "address": o["address"],
                "code": "x", "lines": 1}

    monkeypatch.setattr(Radare2Adapter, "analyze", fake_analyze)
    monkeypatch.setattr(Radare2Adapter, "is_available", lambda self: True)
    asyncio.run(analysis.dispatch(
        "decompile", {"address": "0x1", "path": __file__, "decompiler": "pdg"}))
    assert seen["engine"] == "r2"
