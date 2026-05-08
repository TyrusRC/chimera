"""Unit tests for the ELF persistence scanner."""
from chimera.parsers.elf_persistence_scanner import scan_strings


def _s(value: str, address: str = "0x1000") -> dict:
    return {"value": value, "address": address}


def test_empty_returns_empty():
    assert scan_strings([]) == []


def test_detects_cron_paths():
    out = scan_strings([_s("/etc/cron.d/malicious")])
    assert len(out) == 1
    assert out[0]["category"] == "cron"
    assert "/etc/cron.d/" in out[0]["path"]


def test_detects_ld_preload_env():
    out = scan_strings([_s("LD_PRELOAD=/tmp/x.so:/tmp/y.so")])
    assert len(out) == 1
    assert out[0]["category"] == "ld_preload"


def test_detects_systemd_unit():
    out = scan_strings([_s("/etc/systemd/system/evil.service")])
    assert len(out) == 1
    assert out[0]["category"] == "systemd_unit"


def test_detects_proc_inspect():
    out = scan_strings([_s("/proc/self/maps")])
    assert any(r["category"] == "proc_inspect" for r in out)


def test_one_string_can_match_multiple_categories():
    # rc.local + cron in one string is contrived; use authorized_keys + dev
    out = scan_strings([_s("/dev/mem and .ssh/authorized_keys")])
    cats = {r["category"] for r in out}
    assert "dev_access" in cats
    assert "ssh_authorized" in cats


def test_preserves_address():
    out = scan_strings([_s("/etc/cron.daily/x", address="0xabcd")])
    assert out[0]["string_address"] == "0xabcd"


def test_accepts_string_entry_like_object():
    class FakeStr:
        def __init__(self, value, address):
            self.value = value
            self.address = address
    out = scan_strings([FakeStr("/etc/init.d/foo", "0x42")])
    assert len(out) == 1
    assert out[0]["category"] == "init_d"
    assert out[0]["string_address"] == "0x42"
