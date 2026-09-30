from chimera.dynamic import vm


def test_get_named_provider():
    p = vm.get_provider("virtualbox")
    assert p is not None and p.name == "virtualbox"


def test_unknown_provider_returns_none():
    assert vm.get_provider("nope") is None


def test_auto_returns_first_available(monkeypatch):
    monkeypatch.setattr(vm.VirtualBoxProvider, "available", lambda self: True)
    p = vm.get_provider(None)
    assert p is not None and p.name == "virtualbox"
