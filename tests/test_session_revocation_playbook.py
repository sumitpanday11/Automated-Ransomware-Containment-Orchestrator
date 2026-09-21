import pytest

from app.identity.adapter import IdentityProviderAdapter
from app.identity.service import IdentityService
from app.response.session_revocation_playbook import SessionRevocationPlaybook


class FailingAuthProvider(IdentityProviderAdapter):
    def authenticate(self) -> bool:
        return False

    def lookup_user(self, username: str) -> dict | None:
        return None

    def suspend_user(self, username: str) -> bool:
        return False

    def list_active_sessions(self, username: str) -> list[dict]:
        return []

    def revoke_session(self, username: str, session_id: str) -> bool:
        return False

    def revoke_tokens(self, username: str) -> bool:
        return False


class FailingSessionLookupProvider(IdentityProviderAdapter):
    def authenticate(self) -> bool:
        return True

    def lookup_user(self, username: str) -> dict | None:
        return {"username": username, "status": "active"}

    def suspend_user(self, username: str) -> bool:
        return True

    def list_active_sessions(self, username: str) -> list[dict]:
        raise RuntimeError("simulated session lookup failure")

    def revoke_session(self, username: str, session_id: str) -> bool:
        return False

    def revoke_tokens(self, username: str) -> bool:
        return False


class FailingTokenProvider(IdentityProviderAdapter):
    def authenticate(self) -> bool:
        return True

    def lookup_user(self, username: str) -> dict | None:
        return {"username": username, "status": "active"}

    def suspend_user(self, username: str) -> bool:
        return True

    def list_active_sessions(self, username: str) -> list[dict]:
        return []

    def revoke_session(self, username: str, session_id: str) -> bool:
        return False

    def revoke_tokens(self, username: str) -> bool:
        raise RuntimeError("simulated token revocation failure")


def test_successfully_revokes_sessions_and_tokens() -> None:
    service = IdentityService()
    result = SessionRevocationPlaybook(service).revoke("alice")

    assert result.username == "alice"
    assert result.success is True
    assert result.status == "revoked"
    assert result.revoked_sessions == 2
    assert result.tokens_revoked is True

    session_entries = [
        entry for entry in result.audit_log
        if entry.action == "revoke_session"
    ]

    assert len(session_entries) == 2
    assert all(entry.success for entry in session_entries)

    assert result.audit_log[-1].action == "revoke_tokens"
    assert result.audit_log[-1].success is True


def test_successfully_revokes_single_session_and_tokens() -> None:
    service = IdentityService()
    result = SessionRevocationPlaybook(service).revoke("bob")

    assert result.success is True
    assert result.status == "revoked"
    assert result.revoked_sessions == 1
    assert result.tokens_revoked is True


def test_handles_user_with_no_active_sessions() -> None:
    service = IdentityService()
    result = SessionRevocationPlaybook(service).revoke("admin")

    assert result.success is True
    assert result.status == "revoked"
    assert result.revoked_sessions == 0
    assert result.tokens_revoked is True


def test_returns_user_not_found() -> None:
    service = IdentityService()

    result = SessionRevocationPlaybook(service).revoke("unknown")

    assert result.success is False
    assert result.status == "user_not_found"
    assert result.revoked_sessions == 0
    assert result.tokens_revoked is False


def test_handles_identity_authentication_failure() -> None:
    provider = FailingAuthProvider()
    service = IdentityService(identity_provider=provider)

    result = SessionRevocationPlaybook(service).revoke("alice")

    assert result.success is False
    assert result.status == "authentication_failed"
    assert result.revoked_sessions == 0
    assert result.tokens_revoked is False


def test_handles_session_lookup_failure() -> None:
    provider = FailingSessionLookupProvider()
    service = IdentityService(identity_provider=provider)

    result = SessionRevocationPlaybook(service).revoke("alice")

    assert result.success is False
    assert result.status == "session_lookup_failed"
    assert result.revoked_sessions == 0
    assert result.tokens_revoked is False
    assert result.audit_log[0].action == "list_active_sessions"


def test_handles_token_revocation_failure() -> None:
    provider = FailingTokenProvider()
    service = IdentityService(identity_provider=provider)

    result = SessionRevocationPlaybook(service).revoke("alice")

    assert result.success is False
    assert result.status == "token_revocation_failed"
    assert result.revoked_sessions == 0
    assert result.tokens_revoked is False
    assert result.audit_log[-1].action == "revoke_tokens"
    assert result.audit_log[-1].success is False
    assert "simulated token revocation failure" in result.audit_log[-1].message


def test_rejects_empty_username() -> None:
    service = IdentityService()
    playbook = SessionRevocationPlaybook(service)

    with pytest.raises(ValueError, match="username must not be empty"):
        playbook.revoke("")


def test_rejects_whitespace_username() -> None:
    service = IdentityService()
    playbook = SessionRevocationPlaybook(service)

    with pytest.raises(ValueError, match="username must not be empty"):
        playbook.revoke("   ")
