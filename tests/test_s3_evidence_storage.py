from app.storage.s3.config import S3StorageConfig
from app.storage.s3.mock import MockS3EvidenceStorage
from app.storage.s3.workflow import EvidenceStorageWorkflow


def create_workflow(
    should_fail: bool = False,
) -> EvidenceStorageWorkflow:
    config = S3StorageConfig(
        bucket_name="test-evidence-bucket",
        region="ap-south-1",
        prefix="evidence",
    )

    storage = MockS3EvidenceStorage(
        config=config,
        should_fail=should_fail,
    )

    return EvidenceStorageWorkflow(
        storage=storage,
        config=config,
    )


def test_s3_configuration():
    config = S3StorageConfig(
        bucket_name="forensic-bucket",
        region="ap-south-1",
        prefix="incident-evidence",
    )

    assert config.bucket_name == "forensic-bucket"
    assert config.region == "ap-south-1"
    assert config.prefix == "incident-evidence"


def test_mock_s3_upload():
    workflow = create_workflow()

    result = workflow.store(
        evidence_id="ev-001",
        artifact_type="memory",
        content=b"memory-evidence",
    )

    assert result.status == "stored"
    assert result.error is None
    assert result.upload is not None
    assert result.upload.bucket == "test-evidence-bucket"
    assert result.upload.evidence_id == "ev-001"


def test_unique_evidence_path():
    workflow = create_workflow()

    first = workflow.build_object_key(
        evidence_id="ev-001",
        artifact_type="memory",
    )

    second = workflow.build_object_key(
        evidence_id="ev-001",
        artifact_type="memory",
    )

    assert first != second
    assert first.startswith("evidence/memory/ev-001/")
    assert second.startswith("evidence/memory/ev-001/")


def test_evidence_metadata_is_stored():
    workflow = create_workflow()

    result = workflow.store(
        evidence_id="ev-002",
        artifact_type="host",
        content=b"host-evidence",
        metadata={
            "hostname": "workstation-01",
            "collector": "host_evidence_collector",
        },
    )

    assert result.upload is not None
    assert result.upload.metadata["evidence_id"] == "ev-002"
    assert result.upload.metadata["artifact_type"] == "host"
    assert result.upload.metadata["hostname"] == "workstation-01"
    assert (
        result.upload.metadata["collector"]
        == "host_evidence_collector"
    )


def test_mock_s3_tracks_uploaded_content():
    config = S3StorageConfig(
        bucket_name="test-bucket",
        region="ap-south-1",
    )
    storage = MockS3EvidenceStorage(config=config)
    workflow = EvidenceStorageWorkflow(storage, config)

    content = b"forensic-data"

    result = workflow.store(
        evidence_id="ev-003",
        artifact_type="logs",
        content=content,
    )

    assert result.upload is not None
    assert storage.objects[result.upload.object_key] == content


def test_upload_failure_is_handled():
    workflow = create_workflow(should_fail=True)

    result = workflow.store(
        evidence_id="ev-004",
        artifact_type="memory",
        content=b"evidence",
    )

    assert result.status == "failed"
    assert result.upload is None
    assert result.error == "S3 upload failed"


def test_empty_evidence_id_is_rejected():
    workflow = create_workflow()

    try:
        workflow.store(
            evidence_id="",
            artifact_type="memory",
            content=b"evidence",
        )
        assert False
    except ValueError as exc:
        assert str(exc) == "evidence_id must not be empty"


def test_empty_artifact_type_is_rejected():
    workflow = create_workflow()

    try:
        workflow.store(
            evidence_id="ev-005",
            artifact_type="",
            content=b"evidence",
        )
        assert False
    except ValueError as exc:
        assert str(exc) == "artifact_type must not be empty"


def test_upload_timestamp_is_created():
    workflow = create_workflow()

    result = workflow.store(
        evidence_id="ev-006",
        artifact_type="system",
        content=b"system-evidence",
    )

    assert result.upload is not None
    assert result.upload.uploaded_at is not None
