"""Headless IDAPython: decompile one function to C. Run by `idat -S`.

Reads CHIMERA_IDA_ADDR (hex) + CHIMERA_IDA_OUT (path) from the env; writes the
Hex-Rays pseudocode to the out file (empty on failure) and exits. This runs
inside IDA's interpreter, so its imports (ida_*) are unavailable to the host and
are never imported by chimera itself.
"""
import os

import ida_auto
import ida_hexrays
import idc

ida_auto.auto_wait()
code = ""
try:
    if ida_hexrays.init_hexrays_plugin():
        ea = int(os.environ["CHIMERA_IDA_ADDR"], 16)
        cf = ida_hexrays.decompile(ea)
        code = str(cf) if cf else ""
except Exception:  # noqa: BLE001 — any IDA error → empty output → caller reports failure
    code = ""
with open(os.environ["CHIMERA_IDA_OUT"], "w") as _f:
    _f.write(code)
idc.qexit(0)
