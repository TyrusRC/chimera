"""MCP tool handlers, grouped by what they need to do their job.

Each module exposes ``dispatch(name, arguments)`` and returns None for a
tool it does not own, so `mcp_server` can try each group in turn.
"""
