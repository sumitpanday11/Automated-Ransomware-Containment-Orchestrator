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

    @abstractmethod
    def list_active_sessions(self, username: str) -> list[dict[str, Any]]:
        """List active sessions for a user."""
        raise NotImplementedError

    @abstractmethod
    def revoke_session(self, username: str, session_id: str) -> bool:
        """Revoke a specific active session."""
        raise NotImplementedError

    @abstractmethod
    def revoke_tokens(self, username: str) -> bool:
        """Revoke active tokens for a user."""
        raise NotImplementedError