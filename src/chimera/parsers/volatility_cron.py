"""Recover cron / systemd entries from cached file content."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class CronEntry:
    schedule: str
    user: Optional[str]
    command: str
    source_path: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schedule": self.schedule, "user": self.user,
            "command": self.command, "source_path": self.source_path,
        }


@dataclass
class SystemdUnit:
    name: str
    exec_start: Optional[str]
    user: Optional[str] = None
    wanted_by: Optional[str] = None
    source_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "exec_start": self.exec_start,
            "user": self.user, "wanted_by": self.wanted_by,
            "source_path": self.source_path,
        }


_SYSTEM_CRON_RX = re.compile(
    r"^\s*(?P<sched>@(?:reboot|hourly|daily|weekly|monthly|yearly|annually|midnight)"
    r"|(?:\S+\s+){4}\S+)"
    r"\s+(?P<user>\S+)"
    r"\s+(?P<cmd>.+?)\s*$",
    re.MULTILINE,
)
_USER_CRON_RX = re.compile(
    r"^\s*(?P<sched>@(?:reboot|hourly|daily|weekly|monthly|yearly|annually|midnight)"
    r"|(?:\S+\s+){4}\S+)"
    r"\s+(?P<cmd>.+?)\s*$",
    re.MULTILINE,
)


def parse_cron_text(text: str, source_path: str = "", *, system: bool = True) -> list[CronEntry]:
    if not text:
        return []
    out: list[CronEntry] = []
    rx = _SYSTEM_CRON_RX if system else _USER_CRON_RX
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = rx.match(line)
        if not m:
            continue
        groups = m.groupdict()
        out.append(CronEntry(
            schedule=groups["sched"].strip(),
            user=groups.get("user"),
            command=groups["cmd"].strip(),
            source_path=source_path,
        ))
    return out


_SD_SECTION_RX = re.compile(r"^\s*\[(?P<name>[^\]]+)\]\s*$")
_SD_KV_RX = re.compile(r"^\s*(?P<key>[A-Za-z][A-Za-z0-9_]*)\s*=\s*(?P<value>.*?)\s*$")


def parse_systemd_unit(text: str, source_path: str = "") -> Optional[SystemdUnit]:
    if not text:
        return None
    section: Optional[str] = None
    fields: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        m_sec = _SD_SECTION_RX.match(line)
        if m_sec:
            section = m_sec.group("name")
            continue
        m_kv = _SD_KV_RX.match(line)
        if m_kv and section:
            key = f"{section}.{m_kv.group('key')}"
            fields.setdefault(key, m_kv.group("value"))
    name = source_path.rsplit("/", 1)[-1] if source_path else "unknown.service"
    if not any(k.startswith(("Service.", "Install.")) for k in fields):
        return None
    return SystemdUnit(
        name=name,
        exec_start=fields.get("Service.ExecStart"),
        user=fields.get("Service.User"),
        wanted_by=fields.get("Install.WantedBy"),
        source_path=source_path,
    )
