"""System info routes."""

from __future__ import annotations

from fastapi import APIRouter

from chimera import __version__
from chimera.adapters.radare2 import Radare2Adapter
from chimera.adapters.ghidra import GhidraAdapter
from chimera.adapters.jadx import JadxAdapter
from chimera.adapters.frida_adapter import FridaAdapter
from chimera.adapters.class_dump import ClassDumpAdapter
from chimera.adapters.afl import AFLAdapter
from chimera.adapters.semgrep import SemgrepAdapter

router = APIRouter(prefix="/api", tags=["system"])


@router.get("/info")
async def get_info():
    return {
        "name": "chimera",
        "version": __version__,
        "description": "Mobile reverse engineering platform",
    }


@router.get("/backends")
async def get_backends():
    adapters = [
        Radare2Adapter(), GhidraAdapter(), JadxAdapter(),
        FridaAdapter(), ClassDumpAdapter(), AFLAdapter(), SemgrepAdapter(),
    ]
    return [
        {
            "name": a.name(),
            "available": a.is_available(),
            "formats": a.supported_formats(),
        }
        for a in adapters
    ]
