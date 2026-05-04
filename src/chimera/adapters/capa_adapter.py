"""flare-capa adapter for native ELF/Mach-O capability matching."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from pathlib import Path

from chimera.adapters.base import BackendAdapter, ResourceRequirement, ToolCategory

logger = logging.getLogger(__name__)


class CapaAdapter(BackendAdapter):
    def __init__(self, rules_dir: str | None = None):
        self._rules_dir = rules_dir or os.environ.get("CAPA_RULES_DIR")
        self._capa_bin = shutil.which("capa")

    def name(self) -> str:
        return "capa"

    def is_available(self) -> bool:
        return self._capa_bin is not None

    def supported_formats(self) -> list[str]:
        return ["elf", "macho", "fat", "dylib"]

    def resource_estimate(self, binary_path: str) -> ResourceRequirement:
        size_mb = Path(binary_path).stat().st_size / (1024 * 1024) \
            if Path(binary_path).exists() else 5
        return ResourceRequirement(
            memory_mb=max(512, int(size_mb * 8)),
            category=ToolCategory.LIGHT,
            estimated_seconds=max(5, int(size_mb * 1)),
        )

    async def analyze(self, binary_path: str, options: dict) -> dict:
        if not self.is_available():
            return {"available": False, "capabilities": []}

        cmd = [self._capa_bin, "--json", "--quiet"]
        if self._rules_dir:
            cmd += ["--rules", self._rules_dir]
        cmd.append(binary_path)

        timeout = int(options.get("timeout", 60))
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return {"available": True, "capabilities": [], "error": "timeout"}

        if proc.returncode != 0:
            return {
                "available": True,
                "capabilities": [],
                "error": stderr.decode(errors="replace")[-1000:],
            }

        try:
            payload = json.loads(stdout.decode(errors="replace"))
        except json.JSONDecodeError as exc:
            return {"available": True, "capabilities": [], "error": str(exc)}

        return _normalize_capa_output(payload)

    async def cleanup(self) -> None:
        pass


def _normalize_capa_output(payload: dict) -> dict:
    """Flatten capa's JSON output into chimera's shape.

    capa nests rules under `rules.<rule_name>.matches.<address>`.
    We surface one entry per rule with its namespace, attack/mbc tags,
    and the addresses where matches landed.
    """
    rules = payload.get("rules") or {}
    capabilities: list[dict] = []
    for rule_name, body in rules.items():
        if not isinstance(body, dict):
            continue
        meta = body.get("meta") or {}
        scope = (meta.get("scopes") or {}).get("static") or meta.get("scope")
        is_library = bool(meta.get("lib") or meta.get("is-library-rule"))
        attack = meta.get("attack") or []
        mbc = meta.get("mbc") or []
        namespace = meta.get("namespace") or ""

        addresses: list[str] = []
        matches = body.get("matches") or {}
        if isinstance(matches, dict):
            for raw_addr in matches.keys():
                addresses.append(str(raw_addr))
        elif isinstance(matches, list):
            for entry in matches:
                if isinstance(entry, list) and entry:
                    addresses.append(str(entry[0]))

        capabilities.append({
            "rule": rule_name,
            "namespace": namespace,
            "scope": scope,
            "is_library": is_library,
            "attack": [_short_attack(a) for a in attack],
            "mbc": [_short_mbc(m) for m in mbc],
            "addresses": addresses[:20],
            "address_count": len(addresses),
        })
    capabilities.sort(key=lambda c: (c["is_library"], c["namespace"], c["rule"]))
    return {"available": True, "capabilities": capabilities}


def _short_attack(entry) -> str:
    if isinstance(entry, dict):
        return entry.get("technique") or entry.get("tactic") or str(entry)
    return str(entry)


def _short_mbc(entry) -> str:
    if isinstance(entry, dict):
        return entry.get("behavior") or entry.get("objective") or str(entry)
    return str(entry)
