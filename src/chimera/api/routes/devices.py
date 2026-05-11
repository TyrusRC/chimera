"""Device management API routes."""
from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/api", tags=["devices"])
logger = logging.getLogger(__name__)


@router.get("/devices")
async def list_devices():
    from chimera.device.android import AndroidDeviceManager
    from chimera.device.ios import IOSDeviceManager

    devices = []
    for mgr in [AndroidDeviceManager(), IOSDeviceManager()]:
        if not mgr.is_available:
            continue
        try:
            for d in await mgr.list_devices():
                devices.append({
                    "id": d.id,
                    "platform": d.platform.value,
                    "model": d.model,
                    "os_version": d.os_version,
                    "is_rooted": d.is_rooted,
                    "is_jailbroken": d.is_jailbroken,
                })
        except (OSError, RuntimeError) as e:
            logger.warning("Failed to list devices for %s: %s", type(mgr).__name__, e)
        finally:
            await mgr.cleanup()
    return devices


@router.get("/devices/{device_id}/packages")
async def list_device_packages(device_id: str):
    """Return installed package names on the given device.

    Tries Android first, then iOS. 404 if no device manager is available.
    """
    from chimera.device.android import AndroidDeviceManager
    from chimera.device.ios import IOSDeviceManager

    for mgr in [AndroidDeviceManager(), IOSDeviceManager()]:
        if not mgr.is_available:
            continue
        try:
            pkgs = await mgr.list_packages(device_id)
            await mgr.cleanup()
            return {"packages": list(pkgs)}
        except Exception as e:
            logger.warning("list_packages failed for %s on %s: %s",
                           device_id, type(mgr).__name__, e)
            await mgr.cleanup()
            continue
    raise HTTPException(status_code=404, detail="No device manager available")
