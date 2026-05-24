"""Native-binary unpacking — packer detection + automated unpacking where
the tool exists, manual guidance where it doesn't.

The split is intentional: chimera is happy to call ``upx -d`` for you,
but for VM-protectors (Themida, VMProtect, ASPack) we surface what the
analyst needs to do next rather than ship a half-working unpacker that
will silently corrupt the binary.

Module surface::

    detect_packer(path)       -> Detection
    unpacker_for(packer_name) -> Unpacker | None
    run_unpacker(u, src, dst) -> UnpackResult
    guidance_for(packer_name) -> str | None       # docs for manual paths
"""

from chimera.unpacking.detect import Detection, detect_packer
from chimera.unpacking.unpackers import (
    UnpackError,
    UnpackResult,
    Unpacker,
    guidance_for,
    run_unpacker,
    unpacker_for,
)

__all__ = [
    "Detection",
    "detect_packer",
    "guidance_for",
    "run_unpacker",
    "unpacker_for",
    "UnpackError",
    "UnpackResult",
    "Unpacker",
]
