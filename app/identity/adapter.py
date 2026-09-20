from abc import ABC, abstractmethod
from typing import Any


class IdentityProviderAdapter(ABC):
    """Abstract interface for identity providers such as AD/Azure AD."""

    @abstractmethod
    def authenticate(self) -> bool:
        """Authenticate with the identity provider."""
        raise NotImplementedError

    @abstractmethod
    def lookup_user(self, username: str) -> dict[str, Any] | None:
        """Look up a user by username."""
        raise NotImplementedError

    @abstractmethod
    def suspend_user(self, username: str) -> bool:
        """Suspend a user account."""
        raise NotImplementedError
