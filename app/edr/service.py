from typing import Any

from app.edr.adapter import EDRAdapter
from app.edr.config import EDRSettings
from app.edr.factory import create_edr_provider


class EDRService:
    """Service layer between the orchestrator and EDR providers."""

    def __init__(self, settings: EDRSettings | None = None) -> None:
        self.settings = settings or EDRSettings()
        self.provider: EDRAdapter = create_edr_provider(
            self.settings.provider
        )

    def authenticate(self) -> bool:
        """Authenticate with the configured EDR provider."""
        return self.provider.authenticate()

    def fetch_alerts(self) -> list[dict[str, Any]]:
        """Fetch alerts from the configured EDR provider."""
        return self.provider.fetch_alerts()

    def isolate_host(self, hostname: str) -> bool:
        """Request host isolation through the configured EDR provider."""
        return self.provider.isolate_host(hostname)

    def get_isolation_status(self, hostname: str) -> str:
        """Return host isolation status from the configured EDR provider."""
        return self.provider.get_isolation_status(hostname)
