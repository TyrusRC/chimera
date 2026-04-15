"""Device management API routes."""
from __future__ import annotations
import asyncio
from fastapi import APIRouter
router = APIRouter(prefix="/api", tags=["devices"])

@router.get("/devices")
async def list_devices():
    from chimera.device.android import AndroidDeviceManager
    from chimera.device.ios import IOSDeviceManager
    devices = []
    for mgr in [AndroidDeviceManager(), IOSDeviceManager()]:
        if mgr.is_available:
            try:
                for d in await mgr.list_devices():
                    devices.append({"id": d.id, "platform": d.platform.value, "model": d.model, "os_version": d.os_version, "is_rooted": d.is_rooted, "is_jailbroken": d.is_jailbroken})
            except (OSError, RuntimeError) as e:
                import logging
                logging.getLogger(__name__).warning("Failed to list devices for %s: %s", type(mgr).__name__, e)
    return devices
