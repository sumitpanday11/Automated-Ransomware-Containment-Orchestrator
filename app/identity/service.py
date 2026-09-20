from typing import Any

from app.identity.adapter import IdentityProviderAdapter
from app.identity.factory import create_identity_provider


class IdentityService:
    """Service layer between the orchestrator and identity providers."""

    def __init__(
        self,
        provider: str = "mock",
        identity_provider: IdentityProviderAdapter | None = None,
    ) -> None:
        self.provider = identity_provider or create_identity_provider(provider)

    def authenticate(self) -> bool:
        """Authenticate with the identity provider."""
        return self.provider.authenticate()

    def lookup_user(self, username: str) -> dict[str, Any] | None:
        """Look up a user through the configured provider."""
        return self.provider.lookup_user(username)

    def suspend_user(self, username: str) -> bool:
        """Suspend a user through the configured provider."""
        return self.provider.suspend_user(username)
