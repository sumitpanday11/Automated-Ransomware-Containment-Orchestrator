from dataclasses import dataclass
from typing import Iterable

from app.forensics.collector import Evidence, EvidenceCollector


@dataclass(frozen=True)
class LiveResponseResult:
    """Result of a live response evidence collection run."""

    hostname: str
    evidence: tuple[Evidence, ...]
    failed_collectors: tuple[str, ...]


class LiveResponse:
    """Orchestrate multiple pluggable forensic evidence collectors."""

    def __init__(
        self,
        collectors: Iterable[EvidenceCollector] | None = None,
    ) -> None:
        self.collectors = tuple(collectors or ())

    def collect(self, hostname: str) -> LiveResponseResult:
        """Run all configured collectors against a host."""

        if not hostname.strip():
            raise ValueError("hostname must not be empty")

        evidence: list[Evidence] = []
        failed_collectors: list[str] = []

        for collector in self.collectors:
            try:
                result = collector.collect(hostname)
                evidence.append(result)
            except Exception:
                failed_collectors.append(collector.name)

        return LiveResponseResult(
            hostname=hostname,
            evidence=tuple(evidence),
            failed_collectors=tuple(failed_collectors),
        )