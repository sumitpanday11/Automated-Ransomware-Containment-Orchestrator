from dataclasses import dataclass
from typing import Iterable

from app.forensics.artifacts.collector import Artifact, ArtifactCollector


@dataclass(frozen=True)
class ArtifactCollectionResult:
    """Result of a forensic artifact collection run."""

    hostname: str
    artifacts: tuple[Artifact, ...]
    failed_collectors: tuple[str, ...]


class ArtifactCollectionWorkflow:
    """Orchestrate KAPE-style forensic artifact collectors."""

    def __init__(
        self,
        collectors: Iterable[ArtifactCollector] | None = None,
    ) -> None:
        self.collectors = tuple(collectors or ())

    def collect(self, hostname: str) -> ArtifactCollectionResult:
        """Run configured artifact collectors against a host."""

        if not hostname.strip():
            raise ValueError("hostname must not be empty")

        artifacts: list[Artifact] = []
        failed_collectors: list[str] = []

        for collector in self.collectors:
            try:
                artifact = collector.collect(hostname)
                artifacts.append(artifact)
            except Exception:
                failed_collectors.append(collector.name)

        return ArtifactCollectionResult(
            hostname=hostname,
            artifacts=tuple(artifacts),
            failed_collectors=tuple(failed_collectors),
        )