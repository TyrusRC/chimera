"""Unity IL2CPP analyzer — metadata recovery and native binary annotation."""

from __future__ import annotations

import asyncio
import json
import logging
import math
import shutil
import struct
from pathlib import Path

logger = logging.getLogger(__name__)

# Known IL2CPP metadata magic values (Unity 2018-2022, Unity 2023+).
_IL2CPP_METADATA_MAGICS = {
    b"\xaf\x1b\xb1\xfa",  # Unity 2018-2022
    b"\xfa\xb1\x1b\xaf",  # Big-endian variant occasionally seen
}


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    ent = 0.0
    for f in freq:
        if f:
            p = f / n
            ent -= p * math.log2(p)
    return ent


class UnityAnalyzer:
    def find_il2cpp_binary(self, unpack_dir: Path) -> Path | None:
        unpack_dir = Path(unpack_dir)
        # Direct hits (test fixture and packaged apps put binaries here).
        direct = unpack_dir / "libil2cpp.so"
        if direct.exists():
            return direct
        for arch in ["arm64-v8a", "armeabi-v7a"]:
            p = unpack_dir / "lib" / arch / "libil2cpp.so"
            if p.exists():
                return p
        ga = unpack_dir / "Frameworks" / "GameAssembly.framework" / "GameAssembly"
        if ga.exists():
            return ga
        return None

    def find_metadata(self, unpack_dir: Path) -> Path | None:
        direct = Path(unpack_dir) / "global-metadata.dat"
        if direct.exists() and self._is_valid_metadata(direct):
            return direct
        for meta in Path(unpack_dir).rglob("global-metadata.dat"):
            if self._is_valid_metadata(meta):
                return meta
        return None

    def _is_valid_metadata(self, meta: Path) -> bool:
        if meta.stat().st_size < 100:
            return False
        magic = meta.read_bytes()[:4]
        return magic in _IL2CPP_METADATA_MAGICS

    def detect_encrypted_metadata(self, metadata_path: Path) -> bool:
        """Anti-tamper games encrypt global-metadata.dat — magic is wrong AND entropy is high."""
        data = metadata_path.read_bytes()
        if not data:
            return False
        magic_ok = data[:4] in _IL2CPP_METADATA_MAGICS
        ent = _shannon_entropy(data[:65536])
        return not magic_ok and ent > 7.5

    def unity_version_hint(self, metadata_path: Path) -> int | None:
        """Parse the 4-byte version field at offset 4 when magic is valid."""
        data = metadata_path.read_bytes()[:8]
        if len(data) < 8 or data[:4] not in _IL2CPP_METADATA_MAGICS:
            return None
        return struct.unpack("<I", data[4:8])[0]

    def _write_config(self, config_path: Path, metadata_path: Path) -> None:
        cfg = {"DumpMethod": True, "DumpField": True, "DumpProperty": True}
        version = self.unity_version_hint(metadata_path)
        if version is not None:
            cfg["UnityVersion"] = version
        config_path.write_text(json.dumps(cfg))

    async def run_il2cppdumper(
        self, binary_path: Path, metadata_path: Path, output_dir: Path
    ) -> dict:
        output_dir.mkdir(parents=True, exist_ok=True)

        if self.detect_encrypted_metadata(metadata_path):
            return {
                "dumped": False,
                "encrypted_metadata": True,
                "output_dir": str(output_dir),
                "guidance": (
                    "global-metadata.dat appears encrypted (magic mismatch + high entropy). "
                    "Decryption is deferred to Sub-project 2's IR engine / protection rules."
                ),
            }

        if not shutil.which("Il2CppDumper"):
            return {
                "error": "Il2CppDumper not installed",
                "dumped": False,
                "guidance": (
                    "Il2CppDumper is not installed. Install it and re-run to extract "
                    "class/method/field names from the IL2CPP binary."
                ),
            }

        self._write_config(output_dir / "config.json", metadata_path)

        proc = await asyncio.create_subprocess_exec(
            "Il2CppDumper", str(binary_path), str(metadata_path), str(output_dir),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        dump_cs = output_dir / "dump.cs"
        script_py = output_dir / "script.json"
        err = stderr.decode(errors="replace")[:500] if proc.returncode != 0 else None

        dumped = dump_cs.exists() and dump_cs.stat().st_size > 1024
        if dumped:
            text = dump_cs.read_text(errors="replace")
            if "class " not in text:
                dumped = False

        return {
            "dumped": dumped,
            "encrypted_metadata": False,
            "output_dir": str(output_dir),
            "dump_file": str(dump_cs) if dump_cs.exists() else None,
            "ghidra_script": str(script_py) if script_py.exists() else None,
            "error": err,
            "guidance": None if dumped else (
                "Il2CppDumper did not produce a valid dump.cs. "
                "If the metadata is non-encrypted, this may indicate a Unity-version mismatch — "
                "edit config.json in output_dir and re-run."
            ),
        }
