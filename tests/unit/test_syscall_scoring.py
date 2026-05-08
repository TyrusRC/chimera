from chimera.parsers.syscall_scoring import score_syscalls, SUSPICIOUS_SYSCALLS, BUCKET_WEIGHTS


def test_empty_returns_empty():
    assert score_syscalls([]) == {}


def test_scores_anti_debug():
    out = score_syscalls(["ptrace", "prctl"])
    assert out["anti_debug"]["score"] == 2
    assert "ptrace" in out["anti_debug"]["symbols"]


def test_ptrace_appears_in_multiple_buckets():
    # ptrace is in anti_debug AND process_injection
    out = score_syscalls(["ptrace"])
    assert "anti_debug" in out
    assert "process_injection" in out


def test_scores_network():
    out = score_syscalls(["socket", "connect", "send"])
    assert out["network"]["score"] == 3


def test_unknown_symbols_ignored():
    assert score_syscalls(["nonexistent_function", "free"]) == {}


def test_buckets_present():
    expected = {"anti_debug", "process_injection", "seccomp_evasion",
                "network", "crypto", "persistence"}
    assert expected.issubset(set(SUSPICIOUS_SYSCALLS.keys()))
    assert expected.issubset(set(BUCKET_WEIGHTS.keys()))
