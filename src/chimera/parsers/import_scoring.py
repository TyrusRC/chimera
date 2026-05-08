"""PEStudio-style suspicious-import scoring.

Each bucket maps a category of behavior to the Windows API surface that
characterizes it. We deliberately keep buckets coarse: process injection
is the canonical malware tell on Windows; anti-debug and persistence are
near-universal; network/crypto/filesystem/evasion are softer signals.

The scoring is rule-based and deterministic. No ML, no thresholds —
analysts get a count and a weight per bucket, and decide if the
combination warrants attention.
"""
from __future__ import annotations


SUSPICIOUS_IMPORTS: dict[str, set[str]] = {
    "process_injection": {
        "VirtualAllocEx", "VirtualProtectEx", "WriteProcessMemory",
        "ReadProcessMemory", "CreateRemoteThread", "CreateRemoteThreadEx",
        "QueueUserAPC", "NtMapViewOfSection", "NtUnmapViewOfSection",
        "NtCreateThreadEx", "RtlCreateUserThread",
        "SetThreadContext", "GetThreadContext",
        "SuspendThread", "ResumeThread", "OpenProcess",
    },
    "anti_debug": {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "OutputDebugStringA", "OutputDebugStringW",
        "DebugActiveProcess", "NtSetInformationThread",
        "GetTickCount", "QueryPerformanceCounter",
        "ZwQueryInformationProcess",
    },
    "persistence": {
        "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW",
        "RegOpenKeyExA", "RegOpenKeyExW",
        "CreateServiceA", "CreateServiceW",
        "StartServiceA", "StartServiceW",
        "SetWindowsHookExA", "SetWindowsHookExW",
        "ScheduleTaskCreate", "ITaskScheduler",
    },
    "network": {
        "InternetOpenA", "InternetOpenW",
        "InternetConnectA", "InternetConnectW",
        "HttpOpenRequestA", "HttpOpenRequestW",
        "HttpSendRequestA", "HttpSendRequestW",
        "WinHttpOpen", "WinHttpConnect",
        "WinHttpOpenRequest", "WinHttpSendRequest",
        "socket", "connect", "send", "recv", "WSAStartup",
        "URLDownloadToFileA", "URLDownloadToFileW",
        "DnsQuery_A", "DnsQuery_W",
    },
    "crypto": {
        "CryptAcquireContextA", "CryptAcquireContextW",
        "CryptEncrypt", "CryptDecrypt", "CryptGenKey",
        "CryptHashData", "CryptCreateHash", "CryptDeriveKey",
        "BCryptEncrypt", "BCryptDecrypt", "BCryptGenerateSymmetricKey",
        "BCryptHashData",
    },
    "filesystem": {
        "CreateFileA", "CreateFileW",
        "WriteFile", "ReadFile",
        "MoveFileExA", "MoveFileExW",
        "DeleteFileA", "DeleteFileW",
        "CopyFileA", "CopyFileW",
        "SetFileAttributesA", "SetFileAttributesW",
    },
    "evasion": {
        "Sleep", "SleepEx", "GetTickCount", "GetTickCount64",
        "QueryPerformanceCounter", "GetSystemTime", "NtDelayExecution",
        "GetComputerNameA", "GetComputerNameW",
        "GetUserNameA", "GetUserNameW",
        "GetSystemInfo", "IsWow64Process",
    },
}


BUCKET_WEIGHTS: dict[str, float] = {
    "process_injection": 3.0,
    "anti_debug": 2.0,
    "persistence": 2.0,
    "network": 1.0,
    "crypto": 1.0,
    "filesystem": 0.5,
    "evasion": 1.5,
}


# Build a reverse index for O(1) lookup. Note: a single import name can
# legitimately belong to multiple buckets (e.g., GetTickCount is both
# anti_debug and evasion); the highest-weight bucket wins for the
# `bucket` annotation on the import dict, but every matching bucket
# still counts.
_IMPORT_TO_BUCKETS: dict[str, list[str]] = {}
for _bucket, _names in SUSPICIOUS_IMPORTS.items():
    for _n in _names:
        _IMPORT_TO_BUCKETS.setdefault(_n, []).append(_bucket)


def score_imports(imports: list[dict]) -> dict[str, dict]:
    """Score a list of imports against the suspicious-import buckets.

    Each import dict must have at least a `name` key. Mutates each dict
    to add a `bucket` field set to the highest-weight matching bucket
    (or unset when no match).

    Returns: {bucket: {"imports": [name, ...], "score": int, "weight": float}}.
    """
    out: dict[str, dict] = {}
    for imp in imports:
        name = imp.get("name")
        if not name:
            continue
        matched = _IMPORT_TO_BUCKETS.get(name)
        if not matched:
            continue
        # Annotate this import with its highest-weight bucket.
        best = max(matched, key=lambda b: BUCKET_WEIGHTS.get(b, 0.0))
        imp["bucket"] = best
        for b in matched:
            entry = out.setdefault(b, {
                "imports": [], "score": 0, "weight": BUCKET_WEIGHTS[b],
            })
            entry["imports"].append(name)
            entry["score"] += 1
    return out
