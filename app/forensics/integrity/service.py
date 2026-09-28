from dataclasses import dataclass
from typing import Any

from app.forensics.integrity.hasher import (
    EvidenceHash,
    calculate_sha256,
    create_evidence_hash,
)


@dataclass(frozen=True)
class IntegrityVerificationResult:
    evidence_id: str
    expected_hash: str
    actual_hash: str
    valid: bool
    status: str
    metadata: dict[str, Any]


class EvidenceIntegrityService:
    def create_hash(
        self,
        evidence_id: str,
        content: bytes,
        metadata: dict[str, Any] | None = None,
    ) -> EvidenceHash:
        return create_evidence_hash(
            evidence_id=evidence_id,
            content=content,
            metadata=metadata,
        )

    def verify(
        self,
        evidence_id: str,
        content: bytes,
        expected_hash: str,
    ) -> IntegrityVerificationResult:
        if not evidence_id.strip():
            raise ValueError("evidence_id must not be empty")

        if not expected_hash.strip():
            raise ValueError("expected_hash must not be empty")

        actual_hash = calculate_sha256(content)
        valid = actual_hash == expected_hash

        return IntegrityVerificationResult(
            evidence_id=evidence_id,
            expected_hash=expected_hash,
            actual_hash=actual_hash,
            valid=valid,
            status="valid" if valid else "integrity_failed",
            metadata={
                "hash_algorithm": "SHA-256",
                "verification": "matched" if valid else "mismatched",
            },
        )
