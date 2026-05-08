"""Unit tests for Volatility kernel parsers."""
from chimera.parsers.volatility_kernel import (
    KernelModule, ModuleAnomaly, SyscallHook,
    filter_hooked_syscalls, parse_check_modules, parse_check_syscall, parse_lsmod,
)


def test_parse_lsmod_basic():
    rows = [
        {"Name": "ext4", "Offset": "0xffffffffc0123000", "Size": 524288},
        {"Name": "i915", "Offset": "0xffffffffc0234000", "Size": 1048576},
    ]
    out = parse_lsmod(rows)
    assert len(out) == 2
    assert out[0].name == "ext4"
    assert out[1].size == 1048576


def test_parse_check_modules_records_hidden():
    rows = [
        {"Name": "rootkit_kmod", "Offset": "0xfff",
         "Notes": "in module list but missing from /proc/modules"},
    ]
    out = parse_check_modules(rows)
    assert len(out) == 1
    assert "missing from /proc/modules" in out[0].note


def test_parse_check_modules_supplies_default_note():
    rows = [{"Name": "evil", "Offset": "0x100"}]
    out = parse_check_modules(rows)
    assert "missing" in out[0].note  # default note kicks in


def test_parse_check_syscall_extracts_hooks():
    rows = [
        {"Index": 0, "Name": "sys_read", "Handler": "0xffffffff81000000", "Symbol": "sys_read"},
        {"Index": 1, "Name": "sys_write", "Handler": "0xdeadbeef", "Symbol": "UNKNOWN"},
        {"Index": 2, "Name": "sys_open", "Handler": "0xc0ffee", "Symbol": ""},
    ]
    out = parse_check_syscall(rows)
    assert len(out) == 3
    assert out[0].handler_symbol == "sys_read"
    assert out[1].handler_symbol is None
    assert out[2].handler_symbol is None


def test_filter_hooked_syscalls_returns_only_unresolved():
    hooks = [
        SyscallHook(index=0, name="sys_read", handler_addr="0xfff", handler_symbol="sys_read"),
        SyscallHook(index=1, name="sys_open", handler_addr="0xdeadbeef", handler_symbol=None),
    ]
    hooked = filter_hooked_syscalls(hooks)
    assert len(hooked) == 1
    assert hooked[0].name == "sys_open"


def test_to_dict_round_trip():
    km = KernelModule(name="ext4", address="0xfff", size=1024)
    ma = ModuleAnomaly(name="x", address="0x0", note="hidden")
    sh = SyscallHook(index=0, name="sys_read", handler_addr="0x0", handler_symbol=None)
    assert km.to_dict()["size"] == 1024
    assert ma.to_dict()["note"] == "hidden"
    assert sh.to_dict()["handler_symbol"] is None


def test_empty_inputs():
    assert parse_lsmod([]) == []
    assert parse_check_modules(None) == []
    assert parse_check_syscall(None) == []
