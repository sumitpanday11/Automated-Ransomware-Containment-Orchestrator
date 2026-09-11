from typing import Any

from app.edr.adapter import EDRAdapter


class MockEDRProvider(EDRAdapter):
    """Mock EDR provider for development and testing."""

    def __init__(self) -> None:
        self._authenticated = False

    def authenticate(self) -> bool:
        """Authenticate against the mock EDR provider."""
        self._authenticated = True
        return self._authenticated

    def fetch_alerts(self) -> list[dict[str, Any]]:
        """Return simulated EDR security alerts."""
        if not self._authenticated:
            raise RuntimeError("EDR provider is not authenticated")

        return [
            {
                "alert_id": "MOCK-001",
                "severity": "high",
                "alert_type": "ransomware_behavior",
                "hostname": "workstation-01",
                "status": "new",
            },
            {
                "alert_id": "MOCK-002",
                "severity": "medium",
                "alert_type": "suspicious_process",
                "hostname": "server-01",
                "status": "new",
            },
        ]