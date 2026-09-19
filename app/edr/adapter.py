from abc import ABC, abstractmethod
from typing import Any


class EDRAdapter(ABC):
    """Abstract interface for EDR providers."""

    @abstractmethod
    def authenticate(self) -> bool:
        """Authenticate with the EDR provider."""
        raise NotImplementedError

    @abstractmethod
    def fetch_alerts(self) -> list[dict[str, Any]]:
        """Fetch security alerts from the EDR provider."""
        raise NotImplementedError

    @abstractmethod
    def isolate_host(self, hostname: str) -> bool:
        """Isolate a host from the network."""
        raise NotImplementedError

    @abstractmethod
    def get_isolation_status(self, hostname: str) -> str:
        """Return the current isolation status of a host."""
        raise NotImplementedError
