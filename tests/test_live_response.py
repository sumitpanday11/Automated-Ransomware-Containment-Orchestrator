from app.forensics.collector import Evidence, create_evidence
from app.forensics.collectors.mock import MockEvidenceCollector
from app.forensics.live_response import LiveResponse


def test_create_evidence():
    evidence = create_evidence(
        collector="test_collector",
        evidence_type="processes",
        data={"process_count": 5},
    )

    assert isinstance(evidence, Evidence)
    assert evidence.collector == "test_collector"
    assert evidence.evidence_type == "processes"
    assert evidence.data["process_count"] == 5
    assert evidence.collected_at is not None


def test_mock_collector_collects_evidence():
    collector = MockEvidenceCollector(
        collector_name="process_collector",
        evidence_type_name="processes",
        data={"process_count": 10},
    )

    evidence = collector.collect("workstation-01")

    assert evidence.collector == "process_collector"
    assert evidence.evidence_type == "processes"
    assert evidence.data["process_count"] == 10
    assert evidence.data["hostname"] == "workstation-01"


def test_live_response_runs_multiple_collectors():
    process_collector = MockEvidenceCollector(
        collector_name="process_collector",
        evidence_type_name="processes",
        data={"process_count": 10},
    )

    network_collector = MockEvidenceCollector(
        collector_name="network_collector",
        evidence_type_name="network",
        data={"connection_count": 4},
    )

    response = LiveResponse(
        collectors=[
            process_collector,
            network_collector,
        ]
    )

    result = response.collect("workstation-01")

    assert result.hostname == "workstation-01"
    assert len(result.evidence) == 2
    assert result.failed_collectors == ()

    assert result.evidence[0].collector == "process_collector"
    assert result.evidence[1].collector == "network_collector"


def test_live_response_continues_when_collector_fails():
    class FailingCollector(MockEvidenceCollector):
        def collect(self, hostname: str) -> Evidence:
            raise RuntimeError("collector failed")

    failing_collector = FailingCollector(
        collector_name="failing_collector",
        evidence_type_name="failed",
    )

    working_collector = MockEvidenceCollector(
        collector_name="process_collector",
        evidence_type_name="processes",
        data={"process_count": 10},
    )

    response = LiveResponse(
        collectors=[
            failing_collector,
            working_collector,
        ]
    )

    result = response.collect("workstation-01")

    assert len(result.evidence) == 1
    assert result.evidence[0].collector == "process_collector"
    assert result.failed_collectors == ("failing_collector",)


def test_live_response_rejects_empty_hostname():
    response = LiveResponse()

    try:
        response.collect("")
        assert False
    except ValueError as exc:
        assert str(exc) == "hostname must not be empty"