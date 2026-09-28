from app.forensics.integrity.hasher import (
    calculate_sha256,
    create_evidence_hash,
)
from app.forensics.integrity.service import EvidenceIntegrityService
from app.storage.s3.config import S3StorageConfig
from app.storage.s3.mock import MockS3EvidenceStorage
from app.storage.s3.workflow import EvidenceStorageWorkflow


def test_sha256_hash_is_deterministic() -> None:
    content = b"ransomware evidence"

    first = calculate_sha256(content)
    second = calculate_sha256(content)

    assert first == second
    assert len(first) == 64


def test_create_evidence_hash_contains_metadata() -> None:
    record = create_evidence_hash(
        evidence_id="EV-001",
        content=b"memory evidence",
        metadata={"source": "host-01"},
    )

    assert record.evidence_id == "EV-001"
    assert record.algorithm == "SHA-256"
    assert record.digest == record.metadata["sha256"]
    assert record.metadata["source"] == "host-01"


def test_different_content_produces_different_hash() -> None:
    first = calculate_sha256(b"evidence-a")
    second = calculate_sha256(b"evidence-b")

    assert first != second


def test_integrity_verification_succeeds_for_unchanged_evidence() -> None:
    service = EvidenceIntegrityService()
    content = b"forensic evidence"

    record = service.create_hash("EV-002", content)

    result = service.verify(
        evidence_id="EV-002",
        content=content,
        expected_hash=record.digest,
    )

    assert result.valid is True
    assert result.status == "valid"
    assert result.actual_hash == result.expected_hash


def test_integrity_verification_detects_modified_evidence() -> None:
    service = EvidenceIntegrityService()
    original = b"original evidence"
    modified = b"modified evidence"

    record = service.create_hash("EV-003", original)

    result = service.verify(
        evidence_id="EV-003",
        content=modified,
        expected_hash=record.digest,
    )

    assert result.valid is False
    assert result.status == "integrity_failed"
    assert result.actual_hash != result.expected_hash


def test_hash_before_and_after_mock_s3_upload() -> None:
    service = EvidenceIntegrityService()
    content = b"forensic artifact data"

    record = service.create_hash(
        evidence_id="EV-004",
        content=content,
        metadata={"artifact_type": "memory"},
    )

    storage = MockS3EvidenceStorage(
        config=S3StorageConfig(
            bucket_name="test-evidence-bucket",
            region="ap-south-1",
        )
    )

    workflow = EvidenceStorageWorkflow(
        storage=storage,
        config=storage.config,
    )

    result = workflow.store(
        evidence_id="EV-004",
        artifact_type="memory",
        content=content,
        metadata={
            "sha256": record.digest,
            "hash_algorithm": record.algorithm,
        },
    )

    assert result.status == "stored"
    assert result.upload is not None

    uploaded_content = storage.objects[result.upload.object_key]

    verification = service.verify(
        evidence_id="EV-004",
        content=uploaded_content,
        expected_hash=record.digest,
    )

    assert verification.valid is True


def test_modified_uploaded_evidence_fails_verification() -> None:
    service = EvidenceIntegrityService()
    content = b"original artifact"

    record = service.create_hash(
        evidence_id="EV-005",
        content=content,
    )

    storage = MockS3EvidenceStorage()
    workflow = EvidenceStorageWorkflow(
        storage=storage,
        config=storage.config,
    )

    result = workflow.store(
        evidence_id="EV-005",
        artifact_type="artifact",
        content=content,
    )

    assert result.upload is not None

    uploaded_content = storage.objects[result.upload.object_key]
    tampered_content = uploaded_content + b"-tampered"

    verification = service.verify(
        evidence_id="EV-005",
        content=tampered_content,
        expected_hash=record.digest,
    )

    assert verification.valid is False
    assert verification.status == "integrity_failed"


def test_empty_evidence_id_is_rejected() -> None:
    service = EvidenceIntegrityService()

    try:
        service.create_hash("", b"evidence")
    except ValueError as exc:
        assert str(exc) == "evidence_id must not be empty"
    else:
        raise AssertionError("Expected ValueError")


def test_empty_expected_hash_is_rejected() -> None:
    service = EvidenceIntegrityService()

    try:
        service.verify(
            evidence_id="EV-006",
            content=b"evidence",
            expected_hash="",
        )
    except ValueError as exc:
        assert str(exc) == "expected_hash must not be empty"
    else:
        raise AssertionError("Expected ValueError")
