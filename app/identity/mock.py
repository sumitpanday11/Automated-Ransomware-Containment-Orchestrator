from typing import Any

from app.identity.adapter import IdentityProviderAdapter


class MockIdentityProvider(IdentityProviderAdapter):
    """Mock identity provider for development and testing."""

    def __init__(self) -> None:
        self._authenticated = False
        self._users: dict[str, dict[str, Any]] = {
            "alice": {
                "username": "alice",
                "display_name": "Alice",
                "status": "active",
            },
            "bob": {
                "username": "bob",
                "display_name": "Bob",
                "status": "active",
            },
            "admin": {
                "username": "admin",
                "display_name": "Administrator",
                "status": "active",
            },
        }

    def authenticate(self) -> bool:
        """Authenticate against the mock identity provider."""
        self._authenticated = True
        return self._authenticated

    def lookup_user(self, username: str) -> dict[str, Any] | None:
        """Look up a user by username."""
        if not self._authenticated:
            raise RuntimeError("Identity provider is not authenticated")

        return self._users.get(username)

    def suspend_user(self, username: str) -> bool:
        """Suspend a user account."""
        if not self._authenticated:
            raise RuntimeError("Identity provider is not authenticated")

        user = self._users.get(username)

        if user is None:
            return False

        if user["status"] == "suspended":
            return False

        user["status"] = "suspended"
        return True
