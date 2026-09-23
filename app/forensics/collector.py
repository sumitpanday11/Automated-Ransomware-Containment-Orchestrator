from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class Evidence:
    """Evidence collected from a host during live response."""

    collector: str
    evidence_type: str
    data: dict[str, Any]
    collected_at: datetime


class EvidenceCollector(ABC):
    """Base interface for pluggable forensic evidence collectors."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the collector name."""

    @property
    @abstractmethod
    def evidence_type(self) -> str:
        """Return the type of evidence collected."""

    @abstractmethod
    def collect(self, hostname: str) -> Evidence:
        """Collect evidence from the specified host."""


def create_evidence(
    collector: str,
    evidence_type: str,
    data: dict[str, Any],
) -> Evidence:
    """Create a timestamped evidence record."""

    return Evidence(
        collector=collector,
        evidence_type=evidence_type,
        data=data,
        collected_at=datetime.now(timezone.utc),
    )