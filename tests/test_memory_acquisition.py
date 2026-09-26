from app.forensics.memory.adapter import MemoryEvidence
from app.forensics.memory.mock import MockMemoryAcquisitionAdapter
from app.forensics.memory.workflow import MemoryAcquisitionWorkflow


def test_mock_memory_acquisition_creates_evidence():
    adapter = MockMemoryAcquisitionAdapter(
        acquisition_tool="mock-volatility-source",
        image_reference="evidence/memory/workstation-01.raw",
        image_format="raw",
    )

    evidence = adapter.acquire("workstation-01")

    assert isinstance(evidence, MemoryEvidence)
    assert evidence.hostname == "workstation-01"
    assert evidence.status == "collected"
    assert evidence.acquisition_tool == "mock-volatility-source"
    assert evidence.image_reference == (
        "evidence/memory/workstation-01.raw"
    )
    assert evidence.image_format == "raw"
    assert evidence.metadata["analysis_compatible_with"] == ["Volatility"]
    assert evidence.metadata["hostname"] == "workstation-01"
    assert evidence.collected_at is not None


def test_memory_workflow_collects_evidence():
    adapter = MockMemoryAcquisitionAdapter()
    workflow = MemoryAcquisitionWorkflow(adapter)

    result = workflow.acquire("workstation-01")

    assert result.hostname == "workstation-01"
    assert result.status == "collected"
    assert result.error is None
    assert result.evidence is not None
    assert result.evidence.image_reference is not None


def test_memory_workflow_handles_acquisition_failure():
    adapter = MockMemoryAcquisitionAdapter(
        should_fail=True,
    )
    workflow = MemoryAcquisitionWorkflow(adapter)

    result = workflow.acquire("workstation-01")

    assert result.hostname == "workstation-01"
    assert result.status == "failed"
    assert result.evidence is None
    assert result.error == "memory acquisition failed"


def test_empty_hostname_is_rejected_by_adapter():
    adapter = MockMemoryAcquisitionAdapter()

    try:
        adapter.acquire("")
        assert False
    except ValueError as exc:
        assert str(exc) == "hostname must not be empty"


def test_empty_hostname_is_rejected_by_workflow():
    adapter = MockMemoryAcquisitionAdapter()
    workflow = MemoryAcquisitionWorkflow(adapter)

    try:
        workflow.acquire("")
        assert False
    except ValueError as exc:
        assert str(exc) == "hostname must not be empty"


def test_memory_file_tracking_metadata():
    adapter = MockMemoryAcquisitionAdapter(
        image_reference="evidence/memory/server-01.mem",
        image_format="mem",
    )

    evidence = adapter.acquire("server-01")

    assert evidence.image_reference == "evidence/memory/server-01.mem"
    assert evidence.image_format == "mem"


def test_volatility_compatible_metadata_is_recorded():
    adapter = MockMemoryAcquisitionAdapter(
        metadata={
            "analysis_compatible_with": ["Volatility"],
            "profile": "auto-detect",
        },
    )

    evidence = adapter.acquire("forensic-host")

    assert evidence.metadata["analysis_compatible_with"] == ["Volatility"]
    assert evidence.metadata["profile"] == "auto-detect"