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

        self._sessions: dict[str, list[dict[str, Any]]] = {
            "alice": [
                {"session_id": "alice-session-1", "status": "active"},
                {"session_id": "alice-session-2", "status": "active"},
            ],
            "bob": [
                {"session_id": "bob-session-1", "status": "active"},
            ],
            "admin": [],
        }

        self._revoked_tokens: set[str] = set()

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

    def list_active_sessions(self, username: str) -> list[dict[str, Any]]:
        """List active sessions for a user."""
        if not self._authenticated:
            raise RuntimeError("Identity provider is not authenticated")

        sessions = self._sessions.get(username, [])

        return [
            session.copy()
            for session in sessions
            if session["status"] == "active"
        ]

    def revoke_session(self, username: str, session_id: str) -> bool:
        """Revoke a specific active session."""
        if not self._authenticated:
            raise RuntimeError("Identity provider is not authenticated")

        sessions = self._sessions.get(username, [])

        for session in sessions:
            if session["session_id"] == session_id:
                if session["status"] != "active":
                    return False

                session["status"] = "revoked"
                return True

        return False

    def revoke_tokens(self, username: str) -> bool:
        """Revoke active tokens for a user."""
        if not self._authenticated:
            raise RuntimeError("Identity provider is not authenticated")

        if username not in self._users:
            return False

        self._revoked_tokens.add(username)
        return True