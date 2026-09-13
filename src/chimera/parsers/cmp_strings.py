"""Recover constant immediates the compiler scattered through a function.

Two complementary shapes that both hide data from `get_strings` and FLOSS
(`deobfuscate_strings` recovers WRITTEN stack strings / emulated-decoded strings,
and only the printable ones):

* **Comparison cascade** — a password / key-sequence check compiled as an
  unrolled ``if (buf[0]=='L') if (buf[1]=='L') ...`` leaves the expected value
  only as the immediate operands of a run of ``cmp`` instructions, never
  contiguous. `recover_compare_string` reads them back (e.g. a movement
  sequence like "LLURULDUL").
* **Inline immediate stores** — a hardcoded byte array (key, blob, shellcode,
  lookup table) built with ``mov <size> ptr [buf+i], imm`` stores instead of a
  contiguous ``.data`` blob. `recover_data_bytes` reassembles it (splitting
  word/dword stores into little-endian bytes), and can invert an additive gadget
  (`input[i] = (target - data[i]) & 0xff`) — e.g. when each ``data[i]+input[i]``
  byte is executed, the valid input makes every byte ``0xC3`` = ``ret``.

Both linearly disassemble from a function VA arch-aware (so 32-bit targets work —
the model's x64 disasm path does not). They read the LAST operand token, so a
displacement inside a memory operand (`cmp byte [eax + 0x4c], bl`) is never
mistaken for the value.

NOTE: heuristics following the linear byte stream from `va`, not the CFG — a run
split across non-contiguous blocks may segment; raise `gap`/`max_bytes` then.
"""
from __future__ import annotations

import re

from chimera.patching.binary_patcher import BinaryPatcher, PatchError
from chimera.patching.disasm import DisasmError, make_cs

_IMM_TOKEN = re.compile(r"(?:0x[0-9a-fA-F]+|\d+)\Z")
_SIZE_WIDTH = {"byte": 1, "word": 2, "dword": 4, "qword": 8}
# \b so "word ptr" does not match inside "dword ptr" (substring collision).
_SIZE_KW = re.compile(r"\b(byte|word|dword|qword) ptr")


def _disassemble_function(path, va: int, max_bytes: int):
    """Disassemble up to `max_bytes` from `va`. Returns (insn_iter, arch) on
    success, or ({error dict}, None) — shared by both recovery functions."""
    try:
        p = BinaryPatcher.open(path)
    except PatchError as exc:
        return {"available": True, "error": str(exc)}, None
    arch = p.machine_arch()
    if arch is None:
        return {"available": True, "error": "could not detect the binary's architecture"}, None
    try:
        code = p.read(int(va), max_bytes)
    except PatchError as exc:
        return {"available": True, "error": f"VA {int(va):#x}: {exc}"}, None
    try:
        md = make_cs(arch)
    except DisasmError as exc:
        return {"available": False, "error": str(exc)}, None
    return md.disasm(bytes(code), int(va)), arch


def _last_immediate(op_str: str) -> int | None:
    """Value of the trailing immediate operand, or None if the last operand
    is a register/memory reference (so a memory displacement is never read)."""
    if not op_str:
        return None
    tok = op_str.rsplit(",", 1)[-1].strip()
    if _IMM_TOKEN.fullmatch(tok):
        try:
            return int(tok, 0)
        except ValueError:
            return None
    return None


def recover_compare_string(path, va, *, max_bytes: int = 2048, min_run: int = 4,
                           gap: int = 128, mnemonics=("cmp",)) -> dict:
    """Reconstruct the string(s) implied by a byte-comparison cascade at `va`.

    Disassembles up to `max_bytes` of code from `va`, collects printable-ASCII
    ``cmp``-immediates in address order, and segments them into candidate strings
    (a gap > `gap` bytes between consecutive comparisons starts a new candidate).
    Only candidates of at least `min_run` characters are returned.
    """
    insns, arch = _disassemble_function(path, va, max_bytes)
    if arch is None:
        return insns  # error dict

    want = set(mnemonics)
    hits: list[tuple[int, str]] = []
    for insn in insns:
        if insn.mnemonic in want:
            imm = _last_immediate(insn.op_str)
            if imm is not None and 0x20 <= imm <= 0x7E:
                hits.append((insn.address, chr(imm)))

    runs: list[list[tuple[int, str]]] = []
    cur: list[tuple[int, str]] = []
    for addr, ch in hits:
        if cur and addr - cur[-1][0] > gap:
            runs.append(cur)
            cur = []
        cur.append((addr, ch))
    if cur:
        runs.append(cur)

    candidates = [
        {"string": "".join(c for _, c in r), "start_va": hex(r[0][0]), "count": len(r),
         "chars": [{"va": hex(a), "char": c} for a, c in r]}
        for r in runs if len(r) >= min_run
    ]
    candidates.sort(key=lambda c: c["count"], reverse=True)
    return {
        "available": True, "arch": arch, "function_va": hex(int(va)),
        "candidates": candidates,
        "note": ("strings reconstructed from cmp-immediate cascades — get_strings "
                 "and FLOSS miss these (never contiguous in the file). Enter the "
                 "longest candidate as the expected input / key sequence."),
    }


def _store_immediate(op_str: str) -> tuple[int, int] | None:
    """For a `mov <size> ptr [mem], imm` store: (width_bytes, imm), else None.

    Requires the destination (before the last comma) to be a memory reference and
    the source to be an immediate — so a `mov reg, imm` (not a store) and a store
    of a register are both rejected. Width comes from the size keyword.
    """
    if "[" not in op_str:
        return None
    dest, sep, src = op_str.rpartition(",")
    if not sep or "[" not in dest:      # last operand's dest must be memory
        return None
    src = src.strip()
    if not _IMM_TOKEN.fullmatch(src):
        return None
    try:
        imm = int(src, 0)
    except ValueError:
        return None
    m = _SIZE_KW.search(dest)
    width = _SIZE_WIDTH[m.group(1)] if m else 1
    return width, imm


def recover_data_bytes(path, va, *, max_bytes: int = 4096, max_stores: int = 512,
                       gadget_target: int | None = None) -> dict:
    """Reassemble a byte array built by inline immediate stores at `va`.

    Collects `mov <size> ptr [mem], imm` stores in program order, splitting
    word/dword/qword immediates into little-endian bytes, and concatenates them —
    the array a compiler inlined instead of keeping a contiguous `.data` blob, so
    `get_strings`/FLOSS miss it (mixed / non-printable bytes).

    `gadget_target` inverts an additive gadget: when the binary computes and runs
    `data[i] + input[i]` per byte, the input that makes every byte equal
    `gadget_target` is `(gadget_target - data[i]) & 0xff` — pass 0xC3 for `ret`.
    """
    insns, arch = _disassemble_function(path, va, max_bytes)
    if arch is None:
        return insns  # error dict

    data = bytearray()
    stores: list[dict] = []
    for insn in insns:
        if insn.mnemonic != "mov":
            continue
        si = _store_immediate(insn.op_str)
        if si is None:
            continue
        width, imm = si
        chunk = (imm & ((1 << (8 * width)) - 1)).to_bytes(width, "little")
        data += chunk
        stores.append({"va": hex(insn.address), "width": width, "hex": chunk.hex()})
        if len(stores) >= max_stores:
            break

    result = {
        "available": True, "arch": arch, "function_va": hex(int(va)),
        "byte_count": len(data), "hex": data.hex(), "stores": stores,
        "note": ("byte array reassembled from inline immediate stores — "
                 "get_strings/FLOSS miss mixed/non-printable arrays. Pass "
                 "gadget_target=0xC3 to invert a 'data[i]+input[i] executed as "
                 "code' gadget into the required input."),
    }
    if gadget_target is not None:
        derived = bytes((gadget_target - b) & 0xFF for b in data)
        result["gadget_target"] = hex(gadget_target)
        result["derived_input_hex"] = derived.hex()
        if all(0x20 <= b < 0x7F for b in derived):
            result["derived_input_ascii"] = derived.decode("ascii")
    return result
