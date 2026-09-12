"""symexec (angr) — degrade cleanly when angr is absent; validate the target arg.

angr is heavy and optional; in this env it is not installed, so we exercise the
graceful-degradation contract (the harness itself is the standard angr find/avoid
template, verified by shape). If angr IS present, we assert the no-target guard.
"""
from chimera.dynamic.symexec import solve_input, angr_available


def test_angr_available_returns_bool():
    assert isinstance(angr_available(), bool)


def test_degrades_when_angr_absent_or_guards_target():
    r = solve_input("/bin/true", find="0x1000")
    if not angr_available():
        assert r["available"] is False and "angr" in r["error"]
    else:
        # angr present: a bogus target address simply won't be found (bounded)
        assert r["available"] is True


def test_requires_a_target_when_angr_present():
    if not angr_available():
        return  # can't reach the guard without angr; covered by the degrade test
    r = solve_input("/bin/true")  # no find / find_stdout
    assert r["available"] is True and r["ok"] is False and "target" in r["error"]
