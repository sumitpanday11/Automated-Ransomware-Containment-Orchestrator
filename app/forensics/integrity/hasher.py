import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class EvidenceHash:
    evidence_id: str
    algorithm: str
    digest: str
    created_at: datetime
    metadata: dict[str, Any]


def calculate_sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def create_evidence_hash(
    evidence_id: str,
    content: bytes,
    metadata: dict[str, Any] | None = None,
) -> EvidenceHash:
    if not evidence_id.strip():
        raise ValueError("evidence_id must not be empty")

    digest = calculate_sha256(content)

    return EvidenceHash(
        evidence_id=evidence_id,
        algorithm="SHA-256",
        digest=digest,
        created_at=datetime.now(timezone.utc),
        metadata={
            "evidence_id": evidence_id,
            "hash_algorithm": "SHA-256",
            "sha256": digest,
            **(metadata or {}),
        },
    )
