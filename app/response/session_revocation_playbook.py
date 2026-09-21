from dataclasses import dataclass
import logging

from app.identity.service import IdentityService


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RevocationAuditEntry:
    """Audit record for a session or token revocation action."""

    username: str
    action: str
    success: bool
    status: str
    message: str


@dataclass(frozen=True)
class RevocationResult:
    """Final result of the session and token revocation playbook."""

    username: str
    success: bool
    status: str
    revoked_sessions: int
    tokens_revoked: bool
    audit_log: tuple[RevocationAuditEntry, ...]


class SessionRevocationPlaybook:
    """Revoke active sessions and tokens for a user."""

    def __init__(
        self,
        identity_service: IdentityService | None = None,
    ) -> None:
        self.identity_service = identity_service or IdentityService()

    def revoke(self, username: str) -> RevocationResult:
        """Find and revoke active sessions, then revoke user tokens."""

        if not username.strip():
            raise ValueError("username must not be empty")

        audit_entries: list[RevocationAuditEntry] = []

        if not self.identity_service.authenticate():
            entry = RevocationAuditEntry(
                username=username,
                action="revoke_sessions_and_tokens",
                success=False,
                status="authentication_failed",
                message="Identity provider authentication failed.",
            )

            audit_entries.append(entry)
            logger.error(entry.message)

            return RevocationResult(
                username=username,
                success=False,
                status="authentication_failed",
                revoked_sessions=0,
                tokens_revoked=False,
                audit_log=tuple(audit_entries),
            )

        user = self.identity_service.lookup_user(username)

        if user is None:
            entry = RevocationAuditEntry(
                username=username,
                action="revoke_sessions_and_tokens",
                success=False,
                status="user_not_found",
                message="User account was not found.",
            )

            audit_entries.append(entry)
            logger.warning(entry.message)

            return RevocationResult(
                username=username,
                success=False,
                status="user_not_found",
                revoked_sessions=0,
                tokens_revoked=False,
                audit_log=tuple(audit_entries),
            )

        try:
            sessions = self.identity_service.list_active_sessions(username)
        except Exception as exc:
            entry = RevocationAuditEntry(
                username=username,
                action="list_active_sessions",
                success=False,
                status="error",
                message=f"Active session lookup failed: {exc}",
            )

            audit_entries.append(entry)
            logger.warning(entry.message)

            return RevocationResult(
                username=username,
                success=False,
                status="session_lookup_failed",
                revoked_sessions=0,
                tokens_revoked=False,
                audit_log=tuple(audit_entries),
            )

        revoked_sessions = 0

        for session in sessions:
            session_id = session.get("session_id")

            if not session_id:
                entry = RevocationAuditEntry(
                    username=username,
                    action="revoke_session",
                    success=False,
                    status="invalid_session",
                    message="Active session did not contain a session ID.",
                )

                audit_entries.append(entry)
                logger.warning(entry.message)
                continue

            try:
                success = self.identity_service.revoke_session(
                    username,
                    session_id,
                )
            except Exception as exc:
                entry = RevocationAuditEntry(
                    username=username,
                    action="revoke_session",
                    success=False,
                    status="error",
                    message=f"Session revocation failed: {exc}",
                )

                audit_entries.append(entry)
                logger.warning(entry.message)
                continue

            if success:
                revoked_sessions += 1

                entry = RevocationAuditEntry(
                    username=username,
                    action="revoke_session",
                    success=True,
                    status="revoked",
                    message=f"Session '{session_id}' successfully revoked.",
                )

                audit_entries.append(entry)
                logger.info(entry.message)
            else:
                entry = RevocationAuditEntry(
                    username=username,
                    action="revoke_session",
                    success=False,
                    status="revocation_failed",
                    message=f"Identity provider did not revoke session '{session_id}'.",
                )

                audit_entries.append(entry)
                logger.warning(entry.message)

        try:
            tokens_revoked = self.identity_service.revoke_tokens(username)
        except Exception as exc:
            entry = RevocationAuditEntry(
                username=username,
                action="revoke_tokens",
                success=False,
                status="error",
                message=f"Token revocation failed: {exc}",
            )

            audit_entries.append(entry)
            logger.warning(entry.message)

            return RevocationResult(
                username=username,
                success=False,
                status="token_revocation_failed",
                revoked_sessions=revoked_sessions,
                tokens_revoked=False,
                audit_log=tuple(audit_entries),
            )

        if tokens_revoked:
            entry = RevocationAuditEntry(
                username=username,
                action="revoke_tokens",
                success=True,
                status="revoked",
                message="Active tokens successfully revoked.",
            )

            audit_entries.append(entry)
            logger.info(entry.message)
        else:
            entry = RevocationAuditEntry(
                username=username,
                action="revoke_tokens",
                success=False,
                status="revocation_failed",
                message="Identity provider did not revoke active tokens.",
            )

            audit_entries.append(entry)
            logger.warning(entry.message)

        if tokens_revoked and all(
            entry.success
            for entry in audit_entries
            if entry.action in {"revoke_session", "revoke_tokens"}
        ):
            final_status = "revoked"
            final_success = True
        else:
            final_status = "partial_revocation"
            final_success = False

        return RevocationResult(
            username=username,
            success=final_success,
            status=final_status,
            revoked_sessions=revoked_sessions,
            tokens_revoked=tokens_revoked,
            audit_log=tuple(audit_entries),
        )
