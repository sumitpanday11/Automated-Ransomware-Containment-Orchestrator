from typing import Any

from app.edr.adapter import EDRAdapter


class MockEDRProvider(EDRAdapter):
    """Mock EDR provider for development and testing."""

    def __init__(self) -> None:
        self._authenticated = False
        self._isolated_hosts: set[str] = set()

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

    def isolate_host(self, hostname: str) -> bool:
        """Simulate host isolation."""
        if not self._authenticated:
            raise RuntimeError("EDR provider is not authenticated")

        if not hostname.strip():
            return False

        self._isolated_hosts.add(hostname)
        return True

    def get_isolation_status(self, hostname: str) -> str:
        """Return simulated host isolation status."""
        if not self._authenticated:
            raise RuntimeError("EDR provider is not authenticated")

        if hostname in self._isolated_hosts:
            return "isolated"

        return "not_isolated"
