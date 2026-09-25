from app.forensics.artifacts.collector import Artifact
from app.forensics.artifacts.mock import MockArtifactCollector
from app.forensics.artifacts.workflow import ArtifactCollectionWorkflow


def test_create_mock_artifact():
    collector = MockArtifactCollector(
        collector_name="event_log_collector",
        artifact_type_name="event_logs",
        source_name="Windows Event Logs",
        data={"event_count": 25},
    )

    artifact = collector.collect("workstation-01")

    assert isinstance(artifact, Artifact)
    assert artifact.collector == "event_log_collector"
    assert artifact.artifact_type == "event_logs"
    assert artifact.source == "Windows Event Logs"
    assert artifact.data["event_count"] == 25
    assert artifact.data["hostname"] == "workstation-01"
    assert artifact.collected_at is not None


def test_artifact_workflow_collects_multiple_categories():
    collectors = [
        MockArtifactCollector(
            collector_name="event_logs",
            artifact_type_name="event_logs",
            source_name="Windows Event Logs",
        ),
        MockArtifactCollector(
            collector_name="browser",
            artifact_type_name="browser_artifacts",
            source_name="Browser profile",
        ),
        MockArtifactCollector(
            collector_name="prefetch",
            artifact_type_name="prefetch_metadata",
            source_name="Windows Prefetch",
        ),
        MockArtifactCollector(
            collector_name="persistence",
            artifact_type_name="startup_persistence",
            source_name="Startup locations",
        ),
        MockArtifactCollector(
            collector_name="security",
            artifact_type_name="security_logs",
            source_name="Windows Security Logs",
        ),
        MockArtifactCollector(
            collector_name="system",
            artifact_type_name="system_artifacts",
            source_name="Windows system artifacts",
        ),
    ]

    workflow = ArtifactCollectionWorkflow(collectors)

    result = workflow.collect("workstation-01")

    assert result.hostname == "workstation-01"
    assert len(result.artifacts) == 6
    assert result.failed_collectors == ()

    artifact_types = {
        artifact.artifact_type
        for artifact in result.artifacts
    }

    assert artifact_types == {
        "event_logs",
        "browser_artifacts",
        "prefetch_metadata",
        "startup_persistence",
        "security_logs",
        "system_artifacts",
    }


def test_artifact_workflow_continues_after_collector_failure():
    class FailingCollector(MockArtifactCollector):
        def collect(self, hostname: str) -> Artifact:
            raise RuntimeError("artifact collection failed")

    failing = FailingCollector(
        collector_name="failed_collector",
        artifact_type_name="failed",
    )

    working = MockArtifactCollector(
        collector_name="event_logs",
        artifact_type_name="event_logs",
        source_name="Windows Event Logs",
    )

    workflow = ArtifactCollectionWorkflow(
        [failing, working]
    )

    result = workflow.collect("workstation-01")

    assert len(result.artifacts) == 1
    assert result.artifacts[0].artifact_type == "event_logs"
    assert result.failed_collectors == ("failed_collector",)


def test_empty_hostname_is_rejected():
    workflow = ArtifactCollectionWorkflow()

    try:
        workflow.collect("")
        assert False
    except ValueError as exc:
        assert str(exc) == "hostname must not be empty"


def test_empty_workflow_is_supported():
    workflow = ArtifactCollectionWorkflow()

    result = workflow.collect("workstation-01")

    assert result.hostname == "workstation-01"
    assert result.artifacts == ()
    assert result.failed_collectors == ()