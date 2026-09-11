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