from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from app.storage.s3.adapter import EvidenceUpload, S3EvidenceStorageAdapter
from app.storage.s3.config import S3StorageConfig


@dataclass(frozen=True)
class EvidenceStorageResult:
    """Result of an evidence storage operation."""

    evidence_id: str
    status: str
    upload: EvidenceUpload | None
    error: str | None


class EvidenceStorageWorkflow:
    """Package and securely store forensic evidence."""

    def __init__(
        self,
        storage: S3EvidenceStorageAdapter,
        config: S3StorageConfig,
    ) -> None:
        self.storage = storage
        self.config = config

    def build_object_key(
        self,
        evidence_id: str,
        artifact_type: str,
    ) -> str:
        """Build a unique evidence object path."""

        if not evidence_id.strip():
            raise ValueError("evidence_id must not be empty")

        if not artifact_type.strip():
            raise ValueError("artifact_type must not be empty")

        unique_id = uuid4().hex

        return (
            f"{self.config.prefix}/"
            f"{artifact_type}/"
            f"{evidence_id}/"
            f"{unique_id}.bin"
        )

    def store(
        self,
        evidence_id: str,
        artifact_type: str,
        content: bytes,
        metadata: dict[str, Any] | None = None,
    ) -> EvidenceStorageResult:
        """Store evidence in S3-compatible storage."""

        object_key = self.build_object_key(
            evidence_id=evidence_id,
            artifact_type=artifact_type,
        )

        upload_metadata = {
            "evidence_id": evidence_id,
            "artifact_type": artifact_type,
            **(metadata or {}),
        }

        try:
            upload = self.storage.upload(
                evidence_id=evidence_id,
                content=content,
                object_key=object_key,
                metadata=upload_metadata,
            )

            return EvidenceStorageResult(
                evidence_id=evidence_id,
                status="stored",
                upload=upload,
                error=None,
            )

        except Exception as exc:
            return EvidenceStorageResult(
                evidence_id=evidence_id,
                status="failed",
                upload=None,
                error=str(exc),
            )
