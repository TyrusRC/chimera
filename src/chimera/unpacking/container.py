"""Docker / OCI image extraction for chimera.

Extracts a container's filesystem without running it, identifies interesting
binaries (ELF executables, .NET assemblies, PyInstaller bundles), and returns
a manifest suitable for multi-binary analysis.
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

_INTERESTING_PATTERNS = (
    "*.so", "*.dll", "*.exe", "*.node", "*.pyc",
)


@dataclass
class ContainerTarget:
    path: str
    file_type: str
    size: int
    role: str = ""


@dataclass
class ContainerManifest:
    image: str
    extract_dir: str
    entrypoint: list[str] = field(default_factory=list)
    cmd: list[str] = field(default_factory=list)
    env: list[str] = field(default_factory=list)
    targets: list[ContainerTarget] = field(default_factory=list)
    startup_scripts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "image": self.image,
            "extract_dir": self.extract_dir,
            "entrypoint": self.entrypoint,
            "cmd": self.cmd,
            "env": self.env,
            "targets": [
                {"path": t.path, "file_type": t.file_type,
                 "size": t.size, "role": t.role}
                for t in self.targets
            ],
            "startup_scripts": self.startup_scripts,
        }


def is_container_ref(path: str) -> bool:
    return path.startswith("docker://") or path.startswith("oci://")


def _parse_image_ref(path: str) -> str:
    for prefix in ("docker://", "oci://"):
        if path.startswith(prefix):
            return path[len(prefix):]
    return path


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def _inspect_image(image: str) -> dict:
    result = subprocess.run(
        ["docker", "inspect", image, "--format", "{{json .Config}}"],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"docker inspect failed: {result.stderr.strip()}")
    return json.loads(result.stdout)


def _file_type_quick(path: Path) -> str | None:
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
        if magic[:4] == b"\x7fELF":
            return "elf"
        if magic[:2] == b"MZ":
            return "pe"
        if magic[:2] == b"PK":
            return "zip"
        if magic[:4] == b"\xce\xfa\xed\xfe" or magic[:4] == b"\xfe\xed\xfa\xce":
            return "macho"
        if magic[:4] == b"\xcf\xfa\xed\xfe" or magic[:4] == b"\xfe\xed\xfa\xcf":
            return "macho64"
    except OSError:
        pass
    return None


def _find_executables(root: Path, max_depth: int = 5) -> list[ContainerTarget]:
    targets: list[ContainerTarget] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        rel = str(p.relative_to(root))
        depth = rel.count("/")
        if depth > max_depth:
            continue
        # Skip system libraries and locale data
        if any(skip in rel for skip in (
            "/lib/x86_64-linux-gnu/", "/lib/aarch64-linux-gnu/",
            "/usr/lib/locale/", "/usr/share/", "/var/",
            "/proc/", "/sys/", "/dev/",
        )):
            continue
        ft = _file_type_quick(p)
        if ft in ("elf", "pe", "macho", "macho64"):
            size = p.stat().st_size
            if size < 50_000:
                continue
            role = ""
            name = p.name.lower()
            if name.endswith(".so") or ".so." in name:
                role = "library"
            elif p.stat().st_mode & 0o111:
                role = "executable"
            targets.append(ContainerTarget(
                path=str(p), file_type=ft, size=size, role=role,
            ))
    targets.sort(key=lambda t: t.size, reverse=True)
    return targets


def extract_container(
    image_ref: str,
    out_dir: str | Path | None = None,
) -> ContainerManifest:
    """Extract a Docker image filesystem without running it.

    Returns a manifest with the image config and a list of interesting
    binary targets found in the filesystem.
    """
    if not _docker_available():
        raise RuntimeError(
            "docker CLI not found — install Docker or use "
            "'docker export <container> | tar -xf - -C <dir>' manually"
        )

    image = _parse_image_ref(image_ref)

    # Pull if not present
    pull = subprocess.run(
        ["docker", "image", "inspect", image],
        capture_output=True, timeout=30,
    )
    if pull.returncode != 0:
        logger.info("pulling image %s", image)
        subprocess.run(
            ["docker", "pull", image],
            capture_output=True, timeout=600,
            check=True,
        )

    # Get image config
    config = _inspect_image(image)
    entrypoint = config.get("Entrypoint") or []
    cmd = config.get("Cmd") or []
    env = config.get("Env") or []

    # Create extraction directory
    if out_dir is None:
        safe_name = image.replace("/", "_").replace(":", "_")
        out_dir = Path(tempfile.gettempdir()) / f"chimera_container_{safe_name}"
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Create container (don't start) and export filesystem
    create = subprocess.run(
        ["docker", "create", image],
        capture_output=True, text=True, timeout=60,
    )
    if create.returncode != 0:
        raise RuntimeError(f"docker create failed: {create.stderr.strip()}")
    container_id = create.stdout.strip()

    try:
        export = subprocess.run(
            f"docker export {container_id} | tar -xf - -C {out_dir}",
            shell=True, capture_output=True, timeout=600,
        )
        if export.returncode != 0:
            raise RuntimeError(f"docker export failed: {export.stderr.decode().strip()}")
    finally:
        subprocess.run(
            ["docker", "rm", container_id],
            capture_output=True, timeout=30,
        )

    # Find startup scripts from entrypoint/cmd
    startup_scripts: list[str] = []
    for entry in entrypoint + cmd:
        if entry.endswith(".sh") or entry.endswith(".py"):
            candidate = out_dir / entry.lstrip("/")
            if candidate.exists():
                startup_scripts.append(str(candidate))

    # Find interesting binaries
    targets = _find_executables(out_dir)

    return ContainerManifest(
        image=image,
        extract_dir=str(out_dir),
        entrypoint=entrypoint,
        cmd=cmd,
        env=env,
        targets=targets,
        startup_scripts=startup_scripts,
    )
