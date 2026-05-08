"""Unit tests for the Volatility pagecache files parser."""
from chimera.parsers.volatility_files import CachedFile, parse_pagecache_files


def test_parse_pagecache_files_empty_returns_empty():
    assert parse_pagecache_files([]) == []
    assert parse_pagecache_files(None) == []


def test_parse_pagecache_files_basic_fields():
    rows = [
        {"Inode": 100, "Path": "/etc/cron.d/backdoor", "Size": 256, "Mode": "rw-r--r--"},
        {"Inode": 200, "Path": "/usr/bin/ls", "Size": 130000},
    ]
    out = parse_pagecache_files(rows)
    assert len(out) == 2
    assert out[0].inode == 100
    assert out[0].path == "/etc/cron.d/backdoor"
    assert out[0].size == 256
    assert out[0].mode == "rw-r--r--"
    assert out[1].inode == 200
    assert out[1].mode is None


def test_parse_pagecache_files_alternate_column_names():
    rows = [
        {"InodeNumber": 42, "FilePath": "/etc/ld.so.preload", "Length": 512, "Permissions": "rw-------"},
        {"InodeNumber": 43, "File": "/etc/rc.local", "Length": 128},
    ]
    out = parse_pagecache_files(rows)
    assert len(out) == 2
    assert out[0].inode == 42
    assert out[0].path == "/etc/ld.so.preload"
    assert out[0].size == 512
    assert out[0].mode == "rw-------"
    assert out[1].path == "/etc/rc.local"


def test_parse_pagecache_files_skips_rows_without_path():
    rows = [
        {"Inode": 1, "Size": 100},  # no path key
        {"Inode": 2, "Path": "/etc/passwd", "Size": 2048},
    ]
    out = parse_pagecache_files(rows)
    assert len(out) == 1
    assert out[0].path == "/etc/passwd"


def test_parse_pagecache_files_tolerates_non_int_inode():
    rows = [{"Inode": "not-a-number", "Path": "/proc/1/maps"}]
    out = parse_pagecache_files(rows)
    assert len(out) == 1
    assert out[0].inode is None
    assert out[0].path == "/proc/1/maps"


def test_cached_file_to_dict_round_trip():
    cf = CachedFile(inode=77, path="/etc/crontab", size=1024, mode="rw-r--r--")
    d = cf.to_dict()
    assert d["inode"] == 77
    assert d["path"] == "/etc/crontab"
    assert d["size"] == 1024
    assert d["mode"] == "rw-r--r--"
