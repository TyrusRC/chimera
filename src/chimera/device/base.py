"""Abstract base for device managers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class DevicePlatform(Enum):
    ANDROID = "android"
    IOS = "ios"


@dataclass
class DeviceInfo:
    id: str
    platform: DevicePlatform
    model: Optional[str] = None
    os_version: Optional[str] = None
    arch: Optional[str] = None
    is_rooted: bool = False
    is_jailbroken: bool = False
    frida_version: Optional[str] = None


class DeviceManager(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def is_available(self) -> bool: ...

    @abstractmethod
    async def list_devices(self) -> list[DeviceInfo]: ...

    @abstractmethod
    async def get_device_info(self, device_id: str) -> DeviceInfo | None: ...

    @abstractmethod
    async def list_packages(self, device_id: str) -> list[str]: ...

    @abstractmethod
    async def pull_app(self, device_id: str, package: str, output_dir: str) -> list[str] | None: ...

    @abstractmethod
    async def is_alive(self, device_id: str) -> bool: ...

    @abstractmethod
    async def start_frida_server(self, device_id: str) -> bool: ...

    @abstractmethod
    async def forward_port(self, device_id: str, local: int, remote: int) -> bool: ...

    @abstractmethod
    async def run_command(self, device_id: str, command: str) -> str: ...

    @abstractmethod
    async def cleanup(self) -> None: ...
