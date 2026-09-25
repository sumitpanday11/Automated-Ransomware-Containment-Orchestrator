from typing import Any

from app.forensics.artifacts.collector import (
    Artifact,
    ArtifactCollector,
    create_artifact,
)


class MockArtifactCollector(ArtifactCollector):
    """Mock artifact collector for testing the forensic workflow."""

    def __init__(
        self,
        collector_name: str = "mock_artifact_collector",
        artifact_type_name: str = "mock",
        source_name: str = "test",
        data: dict[str, Any] | None = None,
    ) -> None:
        self._collector_name = collector_name
        self._artifact_type_name = artifact_type_name
        self._source_name = source_name
        self._data = data or {
            "status": "mock_artifact",
        }

    @property
    def name(self) -> str:
        return self._collector_name

    @property
    def artifact_type(self) -> str:
        return self._artifact_type_name

    @property
    def source(self) -> str:
        return self._source_name

    def collect(self, hostname: str) -> Artifact:
        if not hostname.strip():
            raise ValueError("hostname must not be empty")

        data = {
            **self._data,
            "hostname": hostname,
        }

        return create_artifact(
            collector=self.name,
            artifact_type=self.artifact_type,
            source=self.source,
            data=data,
        )