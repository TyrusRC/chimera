"""Abstract base class for all backend tool adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum


class ToolCategory(Enum):
    HEAVY = "heavy"
    LIGHT = "light"


@dataclass
class ResourceRequirement:
    memory_mb: int
    category: ToolCategory
    estimated_seconds: int


class BackendAdapter(ABC):
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def is_available(self) -> bool: ...

    @abstractmethod
    def supported_formats(self) -> list[str]: ...

    @abstractmethod
    def resource_estimate(self, binary_path: str) -> ResourceRequirement: ...

    @abstractmethod
    async def analyze(self, binary_path: str, options: dict) -> dict: ...

    @abstractmethod
    async def cleanup(self) -> None: ...
