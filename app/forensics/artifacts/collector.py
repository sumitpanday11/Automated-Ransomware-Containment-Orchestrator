from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class Artifact:
    """Forensic artifact collected from a host."""

    collector: str
    artifact_type: str
    source: str
    data: dict[str, Any]
    collected_at: datetime


class ArtifactCollector(ABC):
    """Base interface for pluggable forensic artifact collectors."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the collector name."""

    @property
    @abstractmethod
    def artifact_type(self) -> str:
        """Return the type of artifact collected."""

    @property
    @abstractmethod
    def source(self) -> str:
        """Return the artifact source."""

    @abstractmethod
    def collect(self, hostname: str) -> Artifact:
        """Collect an artifact from a host."""


def create_artifact(
    collector: str,
    artifact_type: str,
    source: str,
    data: dict[str, Any],
) -> Artifact:
    """Create a timestamped forensic artifact record."""

    return Artifact(
        collector=collector,
        artifact_type=artifact_type,
        source=source,
        data=data,
        collected_at=datetime.now(timezone.utc),
    )