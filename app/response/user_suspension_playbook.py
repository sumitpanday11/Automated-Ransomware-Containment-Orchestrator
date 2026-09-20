from dataclasses import dataclass
import logging

from app.identity.service import IdentityService


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SuspensionAuditEntry:
    """Audit record for a user suspension action."""

    username: str
    action: str
    success: bool
    status: str
    message: str


@dataclass(frozen=True)
class SuspensionResult:
    """Final result of the user suspension playbook."""

    username: str
    success: bool
    status: str
    audit_log: tuple[SuspensionAuditEntry, ...]


class UserSuspensionPlaybook:
    """Suspend a user through the configured identity service."""

    def __init__(
        self,
        identity_service: IdentityService | None = None,
    ) -> None:
        self.identity_service = identity_service or IdentityService()

    def suspend(self, username: str) -> SuspensionResult:
        """Attempt to suspend a user account."""

        if not username.strip():
            raise ValueError("username must not be empty")

        audit_entries: list[SuspensionAuditEntry] = []

        if not self.identity_service.authenticate():
            entry = SuspensionAuditEntry(
                username=username,
                action="suspend_user",
                success=False,
                status="authentication_failed",
                message="Identity provider authentication failed.",
            )

            audit_entries.append(entry)
            logger.error(entry.message)

            return SuspensionResult(
                username=username,
                success=False,
                status="authentication_failed",
                audit_log=tuple(audit_entries),
            )

        user = self.identity_service.lookup_user(username)

        if user is None:
            entry = SuspensionAuditEntry(
                username=username,
                action="suspend_user",
                success=False,
                status="user_not_found",
                message="User account was not found.",
            )

            audit_entries.append(entry)
            logger.warning(entry.message)

            return SuspensionResult(
                username=username,
                success=False,
                status="user_not_found",
                audit_log=tuple(audit_entries),
            )

        if user.get("status") == "suspended":
            entry = SuspensionAuditEntry(
                username=username,
                action="suspend_user",
                success=False,
                status="already_suspended",
                message="User account is already suspended.",
            )

            audit_entries.append(entry)
            logger.info(entry.message)

            return SuspensionResult(
                username=username,
                success=False,
                status="already_suspended",
                audit_log=tuple(audit_entries),
            )

        try:
            success = self.identity_service.suspend_user(username)
        except Exception as exc:
            entry = SuspensionAuditEntry(
                username=username,
                action="suspend_user",
                success=False,
                status="error",
                message=f"User suspension failed: {exc}",
            )

            audit_entries.append(entry)
            logger.warning(entry.message)

            return SuspensionResult(
                username=username,
                success=False,
                status="error",
                audit_log=tuple(audit_entries),
            )

        if success:
            entry = SuspensionAuditEntry(
                username=username,
                action="suspend_user",
                success=True,
                status="suspended",
                message="User account successfully suspended.",
            )

            audit_entries.append(entry)
            logger.info(entry.message)

            return SuspensionResult(
                username=username,
                success=True,
                status="suspended",
                audit_log=tuple(audit_entries),
            )

        entry = SuspensionAuditEntry(
            username=username,
            action="suspend_user",
            success=False,
            status="suspension_failed",
            message="Identity provider did not suspend the user.",
        )

        audit_entries.append(entry)
        logger.warning(entry.message)

        return SuspensionResult(
            username=username,
            success=False,
            status="suspension_failed",
            audit_log=tuple(audit_entries),
        )
