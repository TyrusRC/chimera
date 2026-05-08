"""Score Linux syscall / libc-call usage into behavior buckets.

Mirrors the import-scoring logic for PE, but for symbols that ELF
malware typically pulls in: ptrace, prctl, process_vm_*, seccomp escapes,
network primitives, crypto.
"""
from __future__ import annotations


SUSPICIOUS_SYSCALLS: dict[str, set[str]] = {
    "anti_debug": {
        "ptrace", "prctl",  # PR_SET_DUMPABLE / PR_SET_PTRACER
        "personality",       # ADDR_NO_RANDOMIZE often set by anti-debug
    },
    "process_injection": {
        "process_vm_readv", "process_vm_writev",
        "ptrace",  # POKETEXT/POKEDATA path
        "memfd_create", "execveat",
    },
    "seccomp_evasion": {
        "seccomp", "prctl",  # PR_SET_NO_NEW_PRIVS / PR_SET_SECCOMP
    },
    "network": {
        "socket", "connect", "bind", "listen", "accept",
        "send", "sendto", "recv", "recvfrom",
        "getaddrinfo", "gethostbyname",
    },
    "crypto": {
        "EVP_EncryptInit_ex", "EVP_DecryptInit_ex",
        "AES_encrypt", "AES_decrypt",
        "CRYPTO_aes_set_encrypt_key",
        "RSA_public_encrypt", "RSA_private_decrypt",
    },
    "persistence": {
        "execve", "execveat", "fork", "vfork", "clone",
        "setuid", "setgid",  # privilege adjustment
    },
}


BUCKET_WEIGHTS: dict[str, float] = {
    "anti_debug": 2.0,
    "process_injection": 3.0,
    "seccomp_evasion": 2.5,
    "network": 1.0,
    "crypto": 1.0,
    "persistence": 1.5,
}


_SYM_TO_BUCKETS: dict[str, list[str]] = {}
for _b, _names in SUSPICIOUS_SYSCALLS.items():
    for _n in _names:
        _SYM_TO_BUCKETS.setdefault(_n, []).append(_b)


def score_syscalls(symbols: list[str]) -> dict[str, dict]:
    """Score a list of symbol names against the suspicious-syscall buckets.

    Returns: {bucket: {"symbols": [name, ...], "score": int, "weight": float}}.
    """
    out: dict[str, dict] = {}
    for sym in symbols:
        if not sym:
            continue
        matched = _SYM_TO_BUCKETS.get(sym)
        if not matched:
            continue
        for b in matched:
            entry = out.setdefault(b, {
                "symbols": [], "score": 0, "weight": BUCKET_WEIGHTS[b],
            })
            entry["symbols"].append(sym)
            entry["score"] += 1
    return out
