import pytest

from app.identity.adapter import IdentityProviderAdapter
from app.identity.service import IdentityService
from app.response.user_suspension_playbook import UserSuspensionPlaybook


class FailingAuthProvider(IdentityProviderAdapter):
    """Identity provider that fails authentication."""

    def authenticate(self) -> bool:
        return False

    def lookup_user(self, username: str) -> dict | None:
        return None

    def suspend_user(self, username: str) -> bool:
        return False


class FailingSuspensionProvider(IdentityProviderAdapter):
    """Identity provider that fails during suspension."""

    def __init__(self) -> None:
        self.authenticated = False

    def authenticate(self) -> bool:
        self.authenticated = True
        return True

    def lookup_user(self, username: str) -> dict | None:
        return {
            "username": username,
            "display_name": "Test User",
            "status": "active",
        }

    def suspend_user(self, username: str) -> bool:
        raise RuntimeError("simulated suspension failure")


def test_successfully_suspends_user() -> None:
    service = IdentityService()

    result = UserSuspensionPlaybook(service).suspend("alice")

    assert result.username == "alice"
    assert result.success is True
    assert result.status == "suspended"
    assert result.audit_log[-1].success is True
    assert result.audit_log[-1].action == "suspend_user"

    user = service.lookup_user("alice")
    assert user is not None
    assert user["status"] == "suspended"


def test_returns_user_not_found() -> None:
    service = IdentityService()

    result = UserSuspensionPlaybook(service).suspend("unknown")

    assert result.success is False
    assert result.status == "user_not_found"
    assert len(result.audit_log) == 1
    assert result.audit_log[0].success is False


def test_returns_already_suspended() -> None:
    service = IdentityService()

    first_result = UserSuspensionPlaybook(service).suspend("alice")
    second_result = UserSuspensionPlaybook(service).suspend("alice")

    assert first_result.success is True
    assert second_result.success is False
    assert second_result.status == "already_suspended"
    assert len(second_result.audit_log) == 1


def test_handles_identity_authentication_failure() -> None:
    provider = FailingAuthProvider()
    service = IdentityService(identity_provider=provider)

    result = UserSuspensionPlaybook(service).suspend("alice")

    assert result.success is False
    assert result.status == "authentication_failed"
    assert result.audit_log[0].action == "suspend_user"


def test_handles_suspension_failure() -> None:
    provider = FailingSuspensionProvider()
    service = IdentityService(identity_provider=provider)

    result = UserSuspensionPlaybook(service).suspend("alice")

    assert result.success is False
    assert result.status == "error"
    assert result.audit_log[0].success is False
    assert "simulated suspension failure" in result.audit_log[0].message


def test_rejects_empty_username() -> None:
    service = IdentityService()
    playbook = UserSuspensionPlaybook(service)

    with pytest.raises(ValueError, match="username must not be empty"):
        playbook.suspend("")


def test_rejects_whitespace_username() -> None:
    service = IdentityService()
    playbook = UserSuspensionPlaybook(service)

    with pytest.raises(ValueError, match="username must not be empty"):
        playbook.suspend("   ")
