"""Parse Volatility 3 process-listing plugin output.

Plugins covered:
  * `linux.pslist.PsList` — flat process list with PID, PPID, COMM, etc.
  * `linux.pstree.PsTree` — same fields but the tree shape is implicit
    via PID/PPID and explicit via the `__children` key on some Vol3
    builds.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class LinuxProcess:
    pid: int
    ppid: int
    name: str
    tgid: Optional[int] = None
    start_time: Optional[str] = None
    exit_state: Optional[str] = None
    is_kernel_thread: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid, "ppid": self.ppid, "name": self.name,
            "tgid": self.tgid, "start_time": self.start_time,
            "exit_state": self.exit_state,
            "is_kernel_thread": self.is_kernel_thread,
        }


@dataclass
class ProcessTreeNode:
    process: LinuxProcess
    children: list["ProcessTreeNode"] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = self.process.to_dict()
        d["children"] = [c.to_dict() for c in self.children]
        return d


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _is_kthread(name: str, ppid: int) -> bool:
    """Heuristic: kernel threads are usually parented by PID 2 (kthreadd)
    OR have a `kworker/`-style name."""
    if ppid == 2:
        return True
    if name and (name.startswith("kworker/") or name in {"kthreadd", "ksoftirqd", "migration", "rcu_sched", "rcu_bh"}):
        return True
    return False


def parse_pslist(rows: list[dict]) -> list[LinuxProcess]:
    """Parse `linux.pslist.PsList` rows into LinuxProcess records.

    Tolerates missing fields and varying column names across Vol3 versions.
    """
    out: list[LinuxProcess] = []
    for row in rows or []:
        pid = _to_int(row.get("PID") or row.get("Pid") or row.get("pid"))
        ppid = _to_int(row.get("PPID") or row.get("Ppid") or row.get("ppid"))
        name = (row.get("COMM") or row.get("Name") or row.get("Comm") or "").strip()
        if not pid:
            continue
        out.append(LinuxProcess(
            pid=pid,
            ppid=ppid,
            name=name,
            tgid=_to_int(row.get("Tgid") or row.get("TGID")) or None,
            start_time=row.get("Created") or row.get("StartTime") or row.get("Start"),
            exit_state=row.get("ExitState") or row.get("Exit"),
            is_kernel_thread=_is_kthread(name, ppid),
        ))
    return out


def parse_pstree(rows: list[dict]) -> list[ProcessTreeNode]:
    """Build a process tree from `linux.pstree.PsTree` output.

    Vol3's pstree may emit either a flat list with a `__children` key
    on each row (newer builds) or just the same shape as pslist (older
    builds). We handle both: if `__children` is present, use it; else
    rebuild the tree from PID/PPID.
    """
    if not rows:
        return []

    # If the first row has __children, trust the explicit tree.
    if "__children" in rows[0] or "Children" in rows[0]:
        return [_node_from_row(r) for r in rows]

    # Otherwise rebuild: index by PID, then attach by PPID.
    procs = parse_pslist(rows)
    by_pid: dict[int, ProcessTreeNode] = {p.pid: ProcessTreeNode(p) for p in procs}
    roots: list[ProcessTreeNode] = []
    for p in procs:
        if p.ppid in by_pid and p.ppid != p.pid:
            by_pid[p.ppid].children.append(by_pid[p.pid])
        else:
            roots.append(by_pid[p.pid])
    return roots


def _node_from_row(row: dict) -> ProcessTreeNode:
    pid = _to_int(row.get("PID") or row.get("pid"))
    ppid = _to_int(row.get("PPID") or row.get("ppid"))
    name = (row.get("COMM") or row.get("Name") or "").strip()
    proc = LinuxProcess(
        pid=pid, ppid=ppid, name=name,
        is_kernel_thread=_is_kthread(name, ppid),
    )
    children_raw = row.get("__children") or row.get("Children") or []
    children = [_node_from_row(c) for c in children_raw]
    return ProcessTreeNode(process=proc, children=children)
