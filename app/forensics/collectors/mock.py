from typing import Any

from app.forensics.collector import Evidence, EvidenceCollector, create_evidence


class MockEvidenceCollector(EvidenceCollector):
    """Mock collector used for forensic framework testing."""

    def __init__(
        self,
        collector_name: str = "mock_collector",
        evidence_type_name: str = "mock",
        data: dict[str, Any] | None = None,
    ) -> None:
        self._collector_name = collector_name
        self._evidence_type_name = evidence_type_name
        self._data = data or {
            "status": "mock_evidence",
            "source": "test",
        }

    @property
    def name(self) -> str:
        return self._collector_name

    @property
    def evidence_type(self) -> str:
        return self._evidence_type_name

    def collect(self, hostname: str) -> Evidence:
        if not hostname.strip():
            raise ValueError("hostname must not be empty")

        data = {
            **self._data,
            "hostname": hostname,
        }

        return create_evidence(
            collector=self.name,
            evidence_type=self.evidence_type,
            data=data,
        )