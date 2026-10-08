"""MCP tool schemas: write-back annotations (rename/comment/type/classify/notes)."""
from __future__ import annotations

from mcp.types import Tool


def tools() -> list[Tool]:
    return [
        Tool(name="rename_function",
             description="Rename the function at ADDRESS. Persists to the project overlay and updates the live model, so the next get_function shows the new name. Survives restart.",
             inputSchema={"type": "object", "properties": {
                 "address": {"type": "string", "description": "Function address (e.g. 0x1234)"},
                 "name": {"type": "string", "description": "New function name"},
             }, "required": ["address", "name"]}),
        Tool(name="set_comment",
             description="Attach a comment at ADDRESS (line 0 = function header). Persisted to the overlay. Use it to record what a routine does as you understand it.",
             inputSchema={"type": "object", "properties": {
                 "address": {"type": "string", "description": "Function address (e.g. 0x1234)"},
                 "text": {"type": "string", "description": "Comment body"},
                 "line": {"type": "integer", "default": 0,
                          "description": "Line/offset within the function; 0 = header/global comment"},
             }, "required": ["address", "text"]}),
        Tool(name="set_function_type",
             description="Pin a C-style signature on the function at ADDRESS (e.g. 'int decode_license(char*)'). Persisted; updates the live model's signature.",
             inputSchema={"type": "object", "properties": {
                 "address": {"type": "string", "description": "Function address (e.g. 0x1234)"},
                 "signature": {"type": "string", "description": "Free-form C signature"},
             }, "required": ["address", "signature"]}),
        Tool(name="set_classification",
             description="Override the classification of the function at ADDRESS (e.g. 'crypto', 'anti_debug', 'license_check'). Persisted; updates the live model.",
             inputSchema={"type": "object", "properties": {
                 "address": {"type": "string", "description": "Function address (e.g. 0x1234)"},
                 "classification": {"type": "string", "description": "Classification label"},
             }, "required": ["address", "classification"]}),
        Tool(name="add_note",
             description="Record a narrative finding in the project notebook, optionally with evidence links to addresses. Survives export/import. Use it to write up how a protection works or how you cracked it.",
             inputSchema={"type": "object", "properties": {
                 "title": {"type": "string"},
                 "body": {"type": "string", "default": ""},
                 "tags": {"type": "array", "items": {"type": "string"}},
                 "evidence": {"type": "array", "items": {"type": "object", "properties": {
                     "address": {"type": "string"}, "line": {"type": "integer"}}},
                     "description": "Evidence items: {address, line}"},
             }, "required": ["title"]}),
        Tool(name="list_annotations",
             description="List every annotation recorded for the loaded binary: renames, comments, types, classifications, notes. Use it to audit what you've already recorded before continuing.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="batch_annotate",
             description="Apply many annotations in one atomic write — far fewer round-trips than one call each when documenting a whole binary. Each op is {op, address, ...}: op='rename' needs 'name'; 'comment' needs 'text' (+optional 'line'); 'type' needs 'signature'; 'classify' needs 'classification'; 'rename_variable' needs 'original'+'new_name'. One bad op is reported, the rest still apply.",
             inputSchema={"type": "object", "properties": {
                 "ops": {"type": "array", "items": {"type": "object", "properties": {
                     "op": {"type": "string",
                            "enum": ["rename", "comment", "type", "classify", "rename_variable"]},
                     "address": {"type": "string"},
                     "name": {"type": "string"}, "text": {"type": "string"},
                     "line": {"type": "integer"}, "signature": {"type": "string"},
                     "classification": {"type": "string"},
                     "original": {"type": "string"}, "new_name": {"type": "string"},
                 }, "required": ["op"]}},
             }, "required": ["ops"]}),
    ]
