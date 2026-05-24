"""Binary patching — in-place writes against PE / ELF / Mach-O.

The module is intentionally minimal:
  * `BinaryPatcher` resolves a virtual address to a file offset, applies
    one or more byte writes, recomputes per-format checksums where the
    runtime loader cares, and emits a new file (or an in-place rewrite).
  * `recipes` ships a small library of canned patches (anti-debug NOPs,
    PLT stub returns) and a loader that applies them by name.
  * The CLI surface (`chimera patch`) plugs both together so analysts can
    `chimera patch app.exe --recipe pe-isdebuggerpresent-nop`.

The patcher does NOT walk the disassembly to *find* targets — it relies
on the model and on capstone-emitted offsets where required. Pattern
search is recipe-local so each recipe can keep its detection logic
beside the patch bytes.
"""

from chimera.patching.binary_patcher import (
    BinaryPatcher,
    PatchError,
    PatchPlan,
    PatchResult,
)

__all__ = ["BinaryPatcher", "PatchError", "PatchPlan", "PatchResult"]
