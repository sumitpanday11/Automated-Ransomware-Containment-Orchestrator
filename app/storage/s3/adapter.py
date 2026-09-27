from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class EvidenceUpload:
    """Metadata describing an uploaded evidence object."""

    bucket: str
    object_key: str
    evidence_id: str
    uploaded_at: datetime
    metadata: dict[str, Any]


class S3EvidenceStorageAdapter(ABC):
    """Interface for S3-compatible evidence storage."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the storage adapter name."""

    @abstractmethod
    def upload(
        self,
        evidence_id: str,
        content: bytes,
        object_key: str,
        metadata: dict[str, Any],
    ) -> EvidenceUpload:
        """Upload evidence and return storage metadata."""


def create_upload_record(
    bucket: str,
    object_key: str,
    evidence_id: str,
    metadata: dict[str, Any],
) -> EvidenceUpload:
    """Create a timestamped evidence upload record."""

    return EvidenceUpload(
        bucket=bucket,
        object_key=object_key,
        evidence_id=evidence_id,
        uploaded_at=datetime.now(timezone.utc),
        metadata=metadata,
    )
