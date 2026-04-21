"""Radare2 adapter — fast triage, disassembly, binary info, strings."""

from __future__ import annotations

import json
import shutil
from typing import Any

import r2pipe

from chimera.adapters.base import BackendAdapter, ResourceRequirement, ToolCategory


class Radare2Adapter(BackendAdapter):
    def name(self) -> str:
        return "radare2"

    def is_available(self) -> bool:
        return shutil.which("r2") is not None or shutil.which("radare2") is not None

    def supported_formats(self) -> list[str]:
        return ["elf", "macho", "dex", "fat", "dylib"]

    def resource_estimate(self, binary_path: str) -> ResourceRequirement:
        return ResourceRequirement(memory_mb=512, category=ToolCategory.LIGHT, estimated_seconds=10)

    async def analyze(self, binary_path: str, options: dict) -> dict:
        mode = options.get("mode", "triage")
        # Drop -2 (was silencing stderr); capture-and-surface is better.
        r2 = r2pipe.open(binary_path, flags=[])
        try:
            if mode == "triage":
                return self._triage(r2)
            elif mode == "strings":
                return self._strings(r2)
            elif mode == "functions":
                return self._functions(r2)
            elif mode == "imports":
                return self._imports(r2)
            elif mode == "full":
                return self._full(r2)
            else:
                return self._triage(r2)
        finally:
            r2.quit()

    async def cleanup(self) -> None:
        pass

    def _triage(self, r2) -> dict:
        info = _cmd_json(r2, "ij")
        strings = _cmd_json(r2, "izj")
        imports = _cmd_json(r2, "iij")
        # Quick function list without full analysis (uses symbol table)
        funcs = _cmd_json(r2, "isj")
        return {
            "info": info.get("bin", {}),
            "core": info.get("core", {}),
            "strings": strings if isinstance(strings, list) else [],
            "imports": imports if isinstance(imports, list) else [],
            "functions": [f for f in (funcs if isinstance(funcs, list) else []) if f.get("type") == "FUNC"],
        }

    def _strings(self, r2) -> dict:
        strings = _cmd_json(r2, "izj")
        return {"strings": strings if isinstance(strings, list) else []}

    def _functions(self, r2) -> dict:
        r2.cmd("aaa")
        funcs = _cmd_json(r2, "aflj")
        return {"functions": funcs if isinstance(funcs, list) else []}

    def _imports(self, r2) -> dict:
        imports = _cmd_json(r2, "iij")
        return {"imports": imports if isinstance(imports, list) else []}

    def _full(self, r2) -> dict:
        # Tune analysis knobs before running deep analysis.
        r2.cmd("e anal.hasnext=true")
        r2.cmd("e anal.pushret=true")
        r2.cmd("e anal.nonull=true")
        # Deep analysis pass + prelude scan + call-xref pass + import table.
        r2.cmd("aaaa")
        r2.cmd("aap")
        r2.cmd("aac")
        r2.cmd("aai")
        # Signature scan (soft-skip if no zignatures configured).
        try:
            r2.cmd("zfs")
        except Exception:
            pass
        result = self._triage(r2)
        result.update(self._strings(r2))
        result.update(self._imports(r2))
        funcs = _cmd_json(r2, "aflj")
        result["functions"] = funcs if isinstance(funcs, list) else []
        return result


def _cmd_json(r2, cmd: str) -> Any:
    try:
        raw = r2.cmd(cmd)
        return json.loads(raw) if raw.strip() else {}
    except (json.JSONDecodeError, ValueError, OSError):
        return {}
