"""Module-singleton accessors for the device managers.

Per-request construction in routes orphans iproxy/adb subprocesses;
keep one instance of each manager type for the FastAPI app lifetime.
"""
from __future__ import annotations

from typing import Optional

from chimera.device.android import AndroidDeviceManager
from chimera.device.ios import IOSDeviceManager

_ANDROID: Optional[AndroidDeviceManager] = None
_IOS: Optional[IOSDeviceManager] = None


def get_android_manager() -> AndroidDeviceManager:
    global _ANDROID
    if _ANDROID is None:
        _ANDROID = AndroidDeviceManager()
    return _ANDROID


def get_ios_manager() -> IOSDeviceManager:
    global _IOS
    if _IOS is None:
        _IOS = IOSDeviceManager()
    return _IOS


async def shutdown_all() -> None:
    global _ANDROID, _IOS
    if _ANDROID is not None:
        try:
            await _ANDROID.cleanup()
        except Exception:
            pass
        _ANDROID = None
    if _IOS is not None:
        try:
            await _IOS.cleanup()
        except Exception:
            pass
        _IOS = None
