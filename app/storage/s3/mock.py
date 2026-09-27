from typing import Any

from app.storage.s3.adapter import (
    EvidenceUpload,
    S3EvidenceStorageAdapter,
    create_upload_record,
)
from app.storage.s3.config import S3StorageConfig


class MockS3EvidenceStorage(S3EvidenceStorageAdapter):
    """Safe in-memory S3 mock for local development and testing."""

    def __init__(
        self,
        config: S3StorageConfig | None = None,
        should_fail: bool = False,
    ) -> None:
        self.config = config or S3StorageConfig(
            bucket_name="test-evidence-bucket",
            region="ap-south-1",
        )
        self.should_fail = should_fail
        self.objects: dict[str, bytes] = {}

    @property
    def name(self) -> str:
        return "mock_s3"

    def upload(
        self,
        evidence_id: str,
        content: bytes,
        object_key: str,
        metadata: dict[str, Any],
    ) -> EvidenceUpload:
        if not evidence_id.strip():
            raise ValueError("evidence_id must not be empty")

        if not object_key.strip():
            raise ValueError("object_key must not be empty")

        if self.should_fail:
            raise RuntimeError("S3 upload failed")

        self.objects[object_key] = content

        return create_upload_record(
            bucket=self.config.bucket_name,
            object_key=object_key,
            evidence_id=evidence_id,
            metadata=metadata,
        )
