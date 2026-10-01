"""Extract payloads from a packet capture — HTTP request/response bodies, raw
TCP stream contents, and the conversation list — via tshark.

The malware-plus-capture challenge class (reconstruct what was exfiltrated /
C2'd from a .pcap) needs the application-layer bytes out of the capture, which
chimera had no tooling for. FLARE-On 13 ch5 "catthief" POSTed the stolen files
as HTTP bodies; recovering them is `extract_http_bodies`. Shells out to tshark
(argv list, never a shell string); reports cleanly when tshark is absent.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


class PcapError(Exception):
    pass


def tshark_available() -> bool:
    return shutil.which("tshark") is not None


def _run(args: list[str], timeout: int = 300) -> str:
    tshark = shutil.which("tshark")
    if not tshark:
        raise PcapError("tshark not found — `apt install tshark`")
    res = subprocess.run([tshark, *args], capture_output=True, text=True, timeout=timeout)
    if res.returncode != 0 and not res.stdout:
        raise PcapError(res.stderr.strip()[:300] or "tshark failed")
    return res.stdout


def _unhex(field: str) -> bytes:
    """tshark hex field (bytes may be ':'-separated or bare) → bytes."""
    s = field.strip().replace(":", "")
    try:
        return bytes.fromhex(s)
    except ValueError:
        return b""


def list_http(path: str) -> list[dict]:
    """HTTP requests + responses: {frame, stream, method, uri, host, code}."""
    out = _run(["-r", path, "-Y", "http", "-T", "fields",
                "-e", "frame.number", "-e", "tcp.stream",
                "-e", "http.request.method", "-e", "http.request.uri",
                "-e", "http.host", "-e", "http.response.code"])
    rows = []
    for line in out.splitlines():
        f = line.split("\t")
        if len(f) < 6:
            f += [""] * (6 - len(f))
        rows.append({"frame": f[0], "stream": f[1], "method": f[2],
                     "uri": f[3], "host": f[4], "code": f[5]})
    return rows


def extract_http_bodies(path: str, out_dir: str | None = None) -> list[dict]:
    """Every HTTP message body (request + response). {stream, uri, size, file?/hex?}.

    `http.file_data` is the de-chunked, de-gzipped body tshark reconstructs.
    """
    out = _run(["-r", path, "-Y", "http.file_data", "-T", "fields",
                "-e", "tcp.stream", "-e", "http.request.uri", "-e", "http.file_data"])
    bodies = []
    seen = 0
    for line in out.splitlines():
        f = line.split("\t")
        if len(f) < 3:
            continue
        stream, uri, hexdata = f[0], f[1], f[2]
        data = _unhex(hexdata)
        if not data:
            continue
        rec = {"stream": stream, "uri": uri, "size": len(data)}
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
            dst = os.path.join(out_dir, f"body_{seen}_stream{stream or 'x'}.bin")
            Path(dst).write_bytes(data)
            rec["file"] = dst
        else:
            rec["hex"] = data[:4096].hex()
        bodies.append(rec)
        seen += 1
    return bodies


def follow_tcp_stream(path: str, stream: int, direction: str = "both") -> bytes:
    """Raw bytes of TCP stream `stream`. direction: both|c2s (client→server)|s2c."""
    out = _run(["-r", path, "-q", "-z", f"follow,tcp,raw,{int(stream)}"])
    # tshark prints a header, then one hex line per segment; client→server lines
    # are un-indented, server→client lines are indented with a tab.
    c2s, s2c = bytearray(), bytearray()
    for line in out.splitlines():
        raw = line.strip()
        if not raw or not all(c in "0123456789abcdefABCDEF" for c in raw):
            continue
        chunk = _unhex(raw)
        (s2c if line.startswith("\t") else c2s).extend(chunk)
    if direction == "c2s":
        return bytes(c2s)
    if direction == "s2c":
        return bytes(s2c)
    return bytes(c2s) + bytes(s2c)


def conversations(path: str) -> str:
    """The tshark TCP conversation table (who talked to whom, byte counts)."""
    return _run(["-r", path, "-q", "-z", "conv,tcp"])
