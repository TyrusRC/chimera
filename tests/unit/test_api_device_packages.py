"""GET /api/devices/{id}/packages returns the package list from the device manager."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from chimera.api.server import create_app


@pytest.fixture
def client():
    return TestClient(create_app())


def test_packages_returns_list_for_android_device(client):
    fake_pkgs = ["com.example.app", "com.android.chrome"]
    with patch("chimera.device.android.AndroidDeviceManager") as Mgr:
        inst = Mgr.return_value
        inst.is_available = True
        inst.list_packages = AsyncMock(return_value=fake_pkgs)
        inst.cleanup = AsyncMock()
        with patch("chimera.device.ios.IOSDeviceManager") as IOSMgr:
            ios = IOSMgr.return_value
            ios.is_available = False
            ios.cleanup = AsyncMock()
            r = client.get("/api/devices/emulator-5554/packages")
    assert r.status_code == 200
    assert r.json() == {"packages": fake_pkgs}


def test_packages_404_when_no_manager_available(client):
    with patch("chimera.device.android.AndroidDeviceManager") as Mgr, \
         patch("chimera.device.ios.IOSDeviceManager") as IOSMgr:
        Mgr.return_value.is_available = False
        IOSMgr.return_value.is_available = False
        Mgr.return_value.cleanup = AsyncMock()
        IOSMgr.return_value.cleanup = AsyncMock()
        r = client.get("/api/devices/emulator-5554/packages")
    assert r.status_code == 404
