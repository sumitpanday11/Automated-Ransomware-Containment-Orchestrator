from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class MemoryEvidence:
    """Metadata describing acquired memory evidence."""

    hostname: str
    status: str
    acquisition_tool: str
    image_reference: str | None
    image_format: str | None
    collected_at: datetime
    metadata: dict[str, Any]


class MemoryAcquisitionAdapter(ABC):
    """Interface for environment-specific memory acquisition."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the acquisition adapter name."""

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Return the memory acquisition tool name."""

    @abstractmethod
    def acquire(self, hostname: str) -> MemoryEvidence:
        """Acquire or register memory evidence for a host."""


def create_memory_evidence(
    hostname: str,
    status: str,
    acquisition_tool: str,
    image_reference: str | None,
    image_format: str | None,
    metadata: dict[str, Any],
) -> MemoryEvidence:
    """Create timestamped memory evidence metadata."""

    return MemoryEvidence(
        hostname=hostname,
        status=status,
        acquisition_tool=acquisition_tool,
        image_reference=image_reference,
        image_format=image_format,
        collected_at=datetime.now(timezone.utc),
        metadata=metadata,
    )
