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

    return None
