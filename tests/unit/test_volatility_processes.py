"""Unit tests for Volatility process parsers."""
from chimera.parsers.volatility_processes import (
    LinuxProcess, ProcessTreeNode, parse_pslist, parse_pstree,
)


def test_parse_pslist_empty_returns_empty():
    assert parse_pslist([]) == []
    assert parse_pslist(None) == []


def test_parse_pslist_extracts_basic_fields():
    rows = [
        {"PID": 1, "PPID": 0, "COMM": "init"},
        {"PID": 100, "PPID": 1, "COMM": "sshd"},
    ]
    out = parse_pslist(rows)
    assert len(out) == 2
    assert out[0].pid == 1 and out[0].name == "init"
    assert out[1].pid == 100 and out[1].name == "sshd"


def test_parse_pslist_marks_kernel_threads():
    rows = [
        {"PID": 2, "PPID": 0, "COMM": "kthreadd"},
        {"PID": 10, "PPID": 2, "COMM": "kworker/0:1"},
        {"PID": 100, "PPID": 1, "COMM": "sshd"},
    ]
    out = parse_pslist(rows)
    by_name = {p.name: p for p in out}
    assert by_name["kthreadd"].is_kernel_thread is True
    assert by_name["kworker/0:1"].is_kernel_thread is True
    assert by_name["sshd"].is_kernel_thread is False


def test_parse_pslist_handles_lowercase_keys():
    rows = [{"pid": 1, "ppid": 0, "comm": "init"}]
    out = parse_pslist(rows)
    assert len(out) == 1
    assert out[0].pid == 1


def test_parse_pslist_skips_rows_with_no_pid():
    rows = [{"COMM": "phantom"}, {"PID": 5, "PPID": 1, "COMM": "real"}]
    out = parse_pslist(rows)
    assert len(out) == 1
    assert out[0].pid == 5


def test_parse_pstree_flat_input_rebuilds_tree():
    rows = [
        {"PID": 1, "PPID": 0, "COMM": "init"},
        {"PID": 2, "PPID": 0, "COMM": "kthreadd"},
        {"PID": 100, "PPID": 1, "COMM": "sshd"},
        {"PID": 101, "PPID": 100, "COMM": "bash"},
    ]
    roots = parse_pstree(rows)
    # Two roots (PPID=0): init, kthreadd
    assert len(roots) == 2
    init = next(r for r in roots if r.process.name == "init")
    assert len(init.children) == 1
    sshd = init.children[0]
    assert sshd.process.name == "sshd"
    assert len(sshd.children) == 1
    assert sshd.children[0].process.name == "bash"


def test_parse_pstree_explicit_children():
    rows = [
        {"PID": 1, "PPID": 0, "COMM": "init", "__children": [
            {"PID": 100, "PPID": 1, "COMM": "sshd", "__children": []},
        ]},
    ]
    roots = parse_pstree(rows)
    assert len(roots) == 1
    assert roots[0].process.name == "init"
    assert roots[0].children[0].process.name == "sshd"


def test_linux_process_to_dict_round_trip():
    p = LinuxProcess(pid=1, ppid=0, name="init", tgid=1, start_time="2024-01-01")
    d = p.to_dict()
    assert d["pid"] == 1
    assert d["start_time"] == "2024-01-01"


def test_process_tree_node_to_dict_includes_children():
    leaf = ProcessTreeNode(LinuxProcess(pid=2, ppid=1, name="child"))
    root = ProcessTreeNode(LinuxProcess(pid=1, ppid=0, name="parent"), children=[leaf])
    d = root.to_dict()
    assert d["pid"] == 1
    assert len(d["children"]) == 1
    assert d["children"][0]["name"] == "child"
