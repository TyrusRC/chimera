"""Parse Volatility 3 forensic-artifact plugin output.

Plugins covered:
  * `linux.bash.Bash` — recovered bash history strings.
  * `linux.sockstat.Sockstat` / `linux.netstat.Netstat` — open sockets.
  * `linux.malfind.Malfind` — VMA regions with executable-and-writable
    permissions, often a malware injection signal.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class BashHistoryEntry:
    pid: int
    process: str
    command: str
    timestamp: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid, "process": self.process,
            "command": self.command, "timestamp": self.timestamp,
        }


@dataclass
class NetworkConnection:
    family: str           # AF_INET / AF_INET6 / AF_UNIX
    protocol: str         # TCP / UDP / RAW
    state: str            # ESTABLISHED / LISTEN / CLOSE_WAIT / ...
    local_addr: str
    local_port: Optional[int]
    remote_addr: str
    remote_port: Optional[int]
    pid: Optional[int]
    process: Optional[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "family": self.family, "protocol": self.protocol, "state": self.state,
            "local": f"{self.local_addr}:{self.local_port}" if self.local_port else self.local_addr,
            "remote": f"{self.remote_addr}:{self.remote_port}" if self.remote_port else self.remote_addr,
            "pid": self.pid, "process": self.process,
        }


@dataclass
class MalfindHit:
    pid: int
    process: str
    start_addr: str       # hex string
    end_addr: str
    protection: str       # "rwx", "r-x", etc.
    has_disasm: bool
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid, "process": self.process,
            "start_addr": self.start_addr, "end_addr": self.end_addr,
            "protection": self.protection,
            "has_disasm": self.has_disasm, "notes": self.notes,
        }


def _to_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_bash(rows: list[dict]) -> list[BashHistoryEntry]:
    out: list[BashHistoryEntry] = []
    for row in rows or []:
        cmd = row.get("Command") or row.get("CommandLine") or row.get("command")
        if not cmd:
            continue
        out.append(BashHistoryEntry(
            pid=_to_int(row.get("PID")) or 0,
            process=row.get("Process") or row.get("COMM") or "",
            command=cmd,
            timestamp=row.get("CommandTime") or row.get("Time") or None,
        ))
    return out


def parse_netstat(rows: list[dict]) -> list[NetworkConnection]:
    out: list[NetworkConnection] = []
    for row in rows or []:
        # Vol3's linux.netstat.Netstat puts the local/remote endpoints
        # in different columns depending on version: 'Source' / 'Local
        # IP', 'Local Port', etc. Be permissive.
        family = row.get("Family") or row.get("Proto") or row.get("Family ") or ""
        protocol = row.get("Protocol") or row.get("Proto") or ""
        state = row.get("State") or ""
        local_addr = (row.get("Source") or row.get("LocalAddr")
                      or row.get("Local") or row.get("Source IP") or "")
        local_port = _to_int(row.get("Source Port") or row.get("LocalPort")
                             or row.get("LPort"))
        remote_addr = (row.get("Destination") or row.get("RemoteAddr")
                       or row.get("Remote") or row.get("Destination IP") or "")
        remote_port = _to_int(row.get("Destination Port") or row.get("RemotePort")
                              or row.get("RPort"))
        out.append(NetworkConnection(
            family=str(family),
            protocol=str(protocol),
            state=str(state),
            local_addr=str(local_addr),
            local_port=local_port,
            remote_addr=str(remote_addr),
            remote_port=remote_port,
            pid=_to_int(row.get("PID") or row.get("Pid")),
            process=row.get("Process") or row.get("COMM") or row.get("Comm"),
        ))
    return out


def parse_malfind(rows: list[dict]) -> list[MalfindHit]:
    out: list[MalfindHit] = []
    for row in rows or []:
        start = row.get("Start") or row.get("StartAddress") or row.get("Vma Start") or ""
        end = row.get("End") or row.get("EndAddress") or row.get("Vma End") or ""
        protection = row.get("Protection") or row.get("Permissions") or ""
        disasm = row.get("Disasm") or row.get("Disassembly") or ""
        out.append(MalfindHit(
            pid=_to_int(row.get("PID") or row.get("Pid")) or 0,
            process=str(row.get("Process") or row.get("COMM") or ""),
            start_addr=str(start),
            end_addr=str(end),
            protection=str(protection),
            has_disasm=bool(disasm),
            notes=str(row.get("Notes") or "")[:200],
        ))
    return out
