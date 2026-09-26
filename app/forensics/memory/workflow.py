from dataclasses import dataclass

from app.forensics.memory.adapter import (
    MemoryAcquisitionAdapter,
    MemoryEvidence,
)


@dataclass(frozen=True)
class MemoryAcquisitionResult:
    """Result of a memory acquisition workflow."""

    hostname: str
    evidence: MemoryEvidence | None
    status: str
    error: str | None


class MemoryAcquisitionWorkflow:
    """Orchestrate environment-specific memory acquisition."""

    def __init__(
        self,
        adapter: MemoryAcquisitionAdapter,
    ) -> None:
        self.adapter = adapter

    def acquire(self, hostname: str) -> MemoryAcquisitionResult:
        """Acquire or register memory evidence for a host."""

        if not hostname.strip():
            raise ValueError("hostname must not be empty")

        try:
            evidence = self.adapter.acquire(hostname)

            return MemoryAcquisitionResult(
                hostname=hostname,
                evidence=evidence,
                status=evidence.status,
                error=None,
            )

        except Exception as exc:
            return MemoryAcquisitionResult(
                hostname=hostname,
                evidence=None,
                status="failed",
                error=str(exc),
            )
