"""Detect the host's GPU and GPU-capable password/hash crackers.

Chimera itself does no cracking — hashcat and John the Ripper already do it
well, and on a CUDA box hashcat drives the GPU with no help from us. What was
missing is *awareness*: an agent driving chimera over MCP had no way to learn
that a 12GB RTX sits idle next to it, so it would grind a keyspace on the CPU
(or worse, try to brute-force something that isn't brute-forceable). This
module answers one question — "what acceleration is on this box, and is it
usable?" — and the `gpu-acceleration` skill turns that answer into a plan.

Read-only and best-effort: every probe is an arg-list subprocess (never a
shell string) guarded so a missing tool degrades to "not present" rather than
raising. No benchmark is run — `nvidia-smi` and `hashcat -I` are both fast.

NOTE: parsing targets NVIDIA + hashcat first (the common CTF/pentest setup).
AMD/Intel and OpenCL-only rigs, and hashcat output-format drift across major
versions, are the known ceilings; whatever fields parse still populate the
report, and `usable` only needs a GPU plus one cracker.
"""
from __future__ import annotations

import logging
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass, field

logger = logging.getLogger(__name__)

_TIMEOUT = 10  # seconds; these probes are quick — never the slow `hashcat -b`


@dataclass
class GpuDevice:
    name: str
    memory_mb: int | None = None
    compute_cap: str | None = None
    driver: str | None = None


@dataclass
class CrackerInfo:
    name: str
    present: bool
    path: str | None = None
    version: str | None = None
    gpu_devices: list[str] = field(default_factory=list)


@dataclass
class GpuReport:
    gpus: list[GpuDevice]
    hashcat: CrackerInfo
    john: CrackerInfo
    usable: bool               # a GPU AND at least one cracker are present
    note: str | None = None

    def as_dict(self) -> dict:
        return asdict(self)

    def summary(self) -> str:
        if self.gpus:
            g = self.gpus[0]
            vram = f", {g.memory_mb} MiB" if g.memory_mb else ""
            cc = f", cc {g.compute_cap}" if g.compute_cap else ""
            gpu = f"{g.name}{vram}{cc}"
            if len(self.gpus) > 1:
                gpu += f" (+{len(self.gpus) - 1} more)"
        else:
            gpu = "no GPU detected"
        crackers = [c.name for c in (self.hashcat, self.john) if c.present]
        tail = "crackers: " + (", ".join(crackers) if crackers else "none")
        verdict = "GPU-accelerated cracking available" if self.usable else "not GPU-crack-ready"
        return f"{gpu} | {tail} | {verdict}"


def parse_nvidia_smi(csv_text: str) -> list[GpuDevice]:
    """Parse `nvidia-smi --query-gpu=name,memory.total,compute_cap,driver_version
    --format=csv,noheader,nounits` output (one GPU per line)."""
    gpus: list[GpuDevice] = []
    for line in csv_text.splitlines():
        parts = [p.strip() for p in line.split(",")]
        if not parts or not parts[0]:
            continue
        name = parts[0]
        mem = _to_int(parts[1]) if len(parts) > 1 else None
        cc = parts[2] or None if len(parts) > 2 else None
        driver = parts[3] or None if len(parts) > 3 else None
        gpus.append(GpuDevice(name=name, memory_mb=mem, compute_cap=cc, driver=driver))
    return gpus


_HASHCAT_NAME = re.compile(r"^\s*Name\.+:\s*(.+?)\s*$")


def parse_hashcat_backends(text: str) -> list[str]:
    """Pull device names from `hashcat -I` (lines like `  Name...........: RTX 3060`)."""
    seen: list[str] = []
    for line in text.splitlines():
        m = _HASHCAT_NAME.match(line)
        if m:
            name = m.group(1)
            if name not in seen:
                seen.append(name)
    return seen


def _to_int(value: str) -> int | None:
    m = re.search(r"\d+", value or "")
    return int(m.group()) if m else None


def _run(cmd: list[str]) -> str | None:
    """Run an arg-list command, returning combined stdout+stderr, or None if the
    binary is missing / errors / times out. Never uses a shell."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=_TIMEOUT, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("probe %s failed: %s", cmd[0], exc)
        return None
    return (proc.stdout or "") + (proc.stderr or "")


def _detect_hashcat() -> CrackerInfo:
    path = shutil.which("hashcat")
    if not path:
        return CrackerInfo(name="hashcat", present=False)
    version = None
    ver = _run(["hashcat", "--version"])
    if ver:
        version = ver.strip().splitlines()[0].strip() or None
    devices: list[str] = []
    info = _run(["hashcat", "-I"])
    if info:
        devices = parse_hashcat_backends(info)
    return CrackerInfo(name="hashcat", present=True, path=path,
                       version=version, gpu_devices=devices)


def _detect_john() -> CrackerInfo:
    path = shutil.which("john")
    if not path:
        return CrackerInfo(name="john", present=False)
    # John prints its banner (with version) to stderr when run bare; the first
    # non-empty line carries "John the Ripper <ver>".
    version = None
    banner = _run(["john", "--list=build-info"]) or _run(["john"])
    if banner:
        for line in banner.splitlines():
            if "John the Ripper" in line:
                version = line.strip()
                break
    return CrackerInfo(name="john", present=True, path=path, version=version)


def detect_gpu() -> GpuReport:
    """Probe the host for a GPU and GPU-capable crackers. Never raises."""
    smi = _run(["nvidia-smi",
                "--query-gpu=name,memory.total,compute_cap,driver_version",
                "--format=csv,noheader,nounits"])
    gpus = parse_nvidia_smi(smi) if smi else []
    hashcat = _detect_hashcat()
    john = _detect_john()

    usable = bool(gpus) and (hashcat.present or john.present)
    note = None
    if gpus and not (hashcat.present or john.present):
        note = ("GPU present but no cracker installed — install hashcat "
                "(apt install hashcat) to use it.")
    elif not gpus and (hashcat.present or john.present):
        note = ("A cracker is installed but no NVIDIA GPU was detected; "
                "cracking will fall back to CPU.")
    elif not gpus and not (hashcat.present or john.present):
        note = "No GPU and no cracker detected — GPU acceleration unavailable."
    return GpuReport(gpus=gpus, hashcat=hashcat, john=john, usable=usable, note=note)
