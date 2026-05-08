"""Unit tests for memory-side persistence finder."""
from chimera.parsers.volatility_files import CachedFile
from chimera.detection_engineering.memory_persistence import (
    MemoryPersistenceFinding,
    find_memory_persistence,
    summarize,
)


def test_find_memory_persistence_empty_input():
    assert find_memory_persistence([]) == []


def test_find_memory_persistence_detects_cron():
    files = [CachedFile(inode=1, path="/etc/cron.d/evil", size=100)]
    findings = find_memory_persistence(files)
    assert len(findings) == 1
    assert findings[0].category == "cron"
    assert findings[0].path == "/etc/cron.d/evil"
    assert findings[0].inode == 1


def test_find_memory_persistence_detects_systemd_unit():
    files = [CachedFile(inode=50, path="/etc/systemd/system/malicious.service", size=512)]
    findings = find_memory_persistence(files)
    assert len(findings) == 1
    assert findings[0].category == "systemd_unit"


def test_find_memory_persistence_first_match_wins():
    # A path that could match multiple patterns should only yield one finding
    files = [CachedFile(inode=10, path="/etc/cron.d/daily-job", size=64)]
    findings = find_memory_persistence(files)
    assert len(findings) == 1


def test_find_memory_persistence_notes_include_size_when_present():
    files = [CachedFile(inode=5, path="/etc/ld.so.preload", size=256)]
    findings = find_memory_persistence(files)
    assert len(findings) == 1
    assert "size=256" in findings[0].notes


def test_find_memory_persistence_notes_empty_when_no_size():
    files = [CachedFile(inode=5, path="/etc/ld.so.preload", size=None)]
    findings = find_memory_persistence(files)
    assert findings[0].notes == ""


def test_find_memory_persistence_ignores_non_persistence_paths():
    files = [
        CachedFile(inode=99, path="/usr/bin/ls", size=130000),
        CachedFile(inode=100, path="/lib/x86_64-linux-gnu/libc.so.6", size=2000000),
    ]
    findings = find_memory_persistence(files)
    assert findings == []


def test_summarize_counts_by_category():
    findings = [
        MemoryPersistenceFinding(category="cron", path="/etc/cron.d/a"),
        MemoryPersistenceFinding(category="cron", path="/etc/cron.d/b"),
        MemoryPersistenceFinding(category="systemd_unit", path="/etc/systemd/system/x.service"),
    ]
    counts = summarize(findings)
    assert counts["cron"] == 2
    assert counts["systemd_unit"] == 1


def test_memory_persistence_finding_to_dict():
    f = MemoryPersistenceFinding(
        category="ld_preload", path="/etc/ld.so.preload", inode=77, notes="file in pagecache (size=512)"
    )
    d = f.to_dict()
    assert d["category"] == "ld_preload"
    assert d["path"] == "/etc/ld.so.preload"
    assert d["inode"] == 77
    assert "size=512" in d["notes"]
