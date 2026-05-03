"""jadx adapter — Java/Kotlin decompilation from DEX (primary Android decompiler)."""

from __future__ import annotations

import asyncio
import os
import shutil
from pathlib import Path

from chimera.adapters.base import BackendAdapter, ResourceRequirement, ToolCategory


class JadxAdapter(BackendAdapter):
    def name(self) -> str:
        return "jadx"

    def is_available(self) -> bool:
        return shutil.which("jadx") is not None

    def supported_formats(self) -> list[str]:
        return ["apk", "dex", "aab"]

    def resource_estimate(self, binary_path: str) -> ResourceRequirement:
        size_mb = Path(binary_path).stat().st_size / (1024 * 1024) if Path(binary_path).exists() else 10
        mem = max(512, int(size_mb * 10))
        seconds = max(10, int(size_mb * 2))
        return ResourceRequirement(memory_mb=mem, category=ToolCategory.LIGHT, estimated_seconds=seconds)

    async def analyze(self, binary_path: str, options: dict) -> dict:
        output_dir = options.get("output_dir")
        if output_dir is None:
            output_dir = Path(binary_path).parent / f"{Path(binary_path).stem}_jadx"
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        threads = os.environ.get("CHIMERA_JADX_THREADS", "2")
        # --deobf-min 2: rename only 1-char names (jadx default is 3, which
        # would also rewrite 2-char names like 'a0'/'b1' that ProGuard
        # actually produces — keep them visible so evidence tests and
        # Sub-project 2's rules can detect the obfuscation pattern).
        cmd = [
            "jadx",
            "--deobf",
            "--deobf-min", "2",
            "--show-bad-code",
            "--log-level", "error",
            "--threads-count", threads,
        ]

        mapping_file = options.get("mapping_file")
        if mapping_file and Path(mapping_file).exists():
            cmd += ["--mappings-path", str(mapping_file)]

        if options.get("kotlin_aware"):
            cmd += [
                "--use-kotlin-methods-for-var-names", "apply",
                "--rename-flags", "valid,printable",
            ]

        # jadx caches deobfuscation decisions under $JADX_CACHE_DIR; pin it
        # per binary so reruns reuse the same renames. jadx ALSO needs a
        # writable $HOME for its general config dir (created on first run);
        # in containers run with `--user <uid>:<gid>` the inherited HOME may
        # be unwritable, so fall back to the cache dir for HOME too. Without
        # this, jadx aborts with NIO `createDirectories` failures and emits
        # zero output even though it returns exit 0.
        env: dict | None = None
        home = os.environ.get("HOME")
        home_writable = bool(home) and os.access(home, os.W_OK)

        deobf_cache_dir = options.get("deobf_cache_dir")
        if deobf_cache_dir:
            Path(deobf_cache_dir).mkdir(parents=True, exist_ok=True)
            env = {**os.environ, "JADX_CACHE_DIR": str(deobf_cache_dir)}
            if not home_writable:
                # Reuse the cache dir as HOME so jadx's general config
                # writes have somewhere to land.
                env["HOME"] = str(deobf_cache_dir)
        elif not home_writable:
            env = {**os.environ, "HOME": "/tmp"}

        cmd += ["--output-dir", str(output_dir), binary_path]

        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        stdout, stderr = await proc.communicate()

        result = {
            "return_code": proc.returncode,
            "output_dir": str(output_dir),
            "sources_dir": str(output_dir / "sources"),
            "resources_dir": str(output_dir / "resources"),
            "mapping_file": str(mapping_file) if mapping_file else None,
            "kotlin_aware": bool(options.get("kotlin_aware")),
        }
        sources = output_dir / "sources"
        if sources.exists():
            java_files = list(sources.rglob("*.java"))
            result["decompiled_files"] = len(java_files)
            result["packages"] = sorted({
                str(f.parent.relative_to(sources)).replace("/", ".").replace("\\", ".")
                for f in java_files
            })
            result["class_basenames"] = sorted({f.stem for f in java_files})
        else:
            result["decompiled_files"] = 0
            result["packages"] = []
            result["class_basenames"] = []
        if proc.returncode != 0:
            result["error"] = stderr.decode(errors="replace")[-2000:]
        return result

    async def cleanup(self) -> None:
        pass
