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
        funcs_raw = _cmd_json(r2, "isj")
        funcs_list = funcs_raw if isinstance(funcs_raw, list) else []

        # ObjC enrichment for SP8 callsite extraction.
        class_symbols: dict[str, str] = {}
        cstring_pool: dict[str, str] = {}
        if isinstance(funcs_list, list):
            for sym in funcs_list:
                name = sym.get("name", "")
                if name.startswith("_OBJC_CLASS_$_"):
                    class_name = name[len("_OBJC_CLASS_$_"):]
                    class_symbols[class_name] = hex(sym.get("vaddr", 0))
        if isinstance(strings, list):
            for s in strings:
                section = s.get("section", "")
                if section in ("__objc_methname", "__cstring") and s.get("string"):
                    cstring_pool[hex(s.get("vaddr", 0))] = s["string"]

        # Per-function disassembly walked via pdfj.
        per_function_disasm: dict[str, dict] = {}
        for sym in funcs_list:
            if sym.get("type") != "FUNC":
                continue
            vaddr = sym.get("vaddr", 0)
            if vaddr == 0:
                continue
            offset_hex = hex(vaddr)
            raw = _cmd_json(r2, f"pdfj @ {offset_hex}")
            if not isinstance(raw, dict):
                continue
            ops_raw = raw.get("ops", [])
            normalized_ops = []
            for op in ops_raw:
                normalized_ops.append(_normalize_op(op))
            per_function_disasm[offset_hex] = {
                "name": raw.get("name", sym.get("name", "")),
                "ops": normalized_ops,
            }

        return {
            "info": info.get("bin", {}),
            "core": info.get("core", {}),
            "strings": strings if isinstance(strings, list) else [],
            "imports": imports if isinstance(imports, list) else [],
            "functions": [f for f in funcs_list if f.get("type") == "FUNC"],
            "per_function_disasm": per_function_disasm,
            "class_symbols": class_symbols,
            "cstring_pool": cstring_pool,
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


def _normalize_op(op: dict) -> dict:
    """Convert an r2 pdfj op dict into the extractor's expected shape.

    Output: {"offset": int, "opcode": str, "operands": [str|int, ...],
             "target_sym": str | None}
    """
    disasm = op.get("disasm", op.get("opcode", "")).strip()
    parts = disasm.replace(",", "").split()
    opcode = parts[0] if parts else ""
    operands: list = []
    for tok in parts[1:]:
        # int operand: 0x... hex literal
        if tok.startswith("0x"):
            try:
                operands.append(int(tok, 16))
                continue
            except ValueError:
                pass
        # int operand: bare decimal
        if tok.lstrip("-").isdigit():
            try:
                operands.append(int(tok))
                continue
            except ValueError:
                pass
        # Strip square brackets ([x0, 0x40] → x0, 0x40)
        operands.append(tok.strip("[]"))
    return {
        "offset": op.get("offset", 0),
        "opcode": opcode,
        "operands": operands,
        "target_sym": op.get("fcn_call") or op.get("flag") or None,
    }
