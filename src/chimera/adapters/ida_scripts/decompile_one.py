"""Headless IDAPython: decompile one function to C. Run by `idat -S`.

The target address and output path are substituted into the two code lines
below by the adapter before the script runs (WSL cannot pass env vars to a
Windows idat, so the values are baked in rather than read from the
environment). NOTE: the placeholder tokens must appear ONLY in code, never in
this docstring or a plain string — a substituted Windows path carries
backslashes that would become invalid \\escape sequences in a non-raw literal.
This runs inside IDA's interpreter, so its ida_* imports are unavailable to the
host and are never imported by chimera itself.
"""
import ida_auto
import ida_hexrays
import idc

ida_auto.auto_wait()
code = ""
try:
    if ida_hexrays.init_hexrays_plugin():
        cf = ida_hexrays.decompile(int("__CHIMERA_ADDR__", 16))
        code = str(cf) if cf else ""
except Exception:  # noqa: BLE001 — any IDA error → empty output → caller reports failure
    code = ""
with open(r"__CHIMERA_OUT__", "w") as _f:
    _f.write(code)
idc.qexit(0)
