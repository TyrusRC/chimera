"""Static unpacking tools: peel layered/marshalled Python without running it.

Returns None when the tool is not one of this module's, so the server can
try the next handler group.
"""
from __future__ import annotations

import logging
from pathlib import Path

from mcp.types import TextContent

from chimera import mcp_session as mcpstate

logger = logging.getLogger(__name__)


async def dispatch(name: str, arguments: dict) -> list[TextContent] | None:
    if name == "py_unwrap":
        from chimera.unpacking.pybytecode import disassemble, unwrap

        path = arguments["path"]
        if not Path(path).exists():
            return mcpstate.error(f"file not found: {path}")

        result = unwrap(path)
        if result.error and result.root is None:
            return mcpstate.error(result.error)

        payload = result.to_dict()
        if arguments.get("disasm"):
            payload["disassembly"] = [
                {"name": cn.name, "text": disassemble(cn.code_obj)}
                for cn in result.code_nodes()
            ]
        return mcpstate.json_reply(payload)

    if name == "pdf_tour":
        from chimera.unpacking.pdf import pdf_tour

        path = arguments["path"]
        if not Path(path).exists():
            return mcpstate.error(f"file not found: {path}")

        tour = pdf_tour(
            path,
            password=str(arguments.get("password", "")).encode(),
            extract_images_dir=arguments.get("extract_images_dir"),
        )
        return mcpstate.json_reply(tour.to_dict())

    if name == "evm_tour":
        from chimera.parsers.evm import (
            EvmRevert, EvmUnsupported, evm_tour, run_pure, split_deploy_runtime,
        )

        source = arguments["source"]
        p = Path(source)
        try:
            is_file = p.exists()
        except OSError:                    # bytecode hex is longer than a filename
            is_file = False
        if is_file:
            raw = p.read_bytes()
            text = raw.decode("ascii", "ignore").strip()
            code = (bytes.fromhex(text[2:] if text.startswith("0x") else text)
                    if text and all(c in "0123456789abcdefABCDEF" for c in text)
                    else raw)
        else:
            try:
                code = bytes.fromhex(source[2:] if source.startswith("0x") else source)
            except ValueError:
                return mcpstate.error(f"not a file and not valid hex: {source[:40]}")

        calldata = arguments.get("calldata")
        if calldata is not None:
            runtime, _ = split_deploy_runtime(code)
            cd = bytes.fromhex(calldata[2:] if calldata.startswith("0x") else calldata)
            try:
                out = run_pure(runtime, cd)
            except (EvmUnsupported, EvmRevert, ValueError) as exc:
                return mcpstate.error(f"pure-run failed: {exc}")
            return mcpstate.json_reply({"return": "0x" + (out or b"").hex()})

        return mcpstate.json_reply(evm_tour(code).to_dict())

    return None
