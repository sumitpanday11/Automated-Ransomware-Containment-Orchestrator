from dataclasses import dataclass
import logging

from app.edr.service import EDRService


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class IsolationAuditEntry:
    """Audit record for a host isolation attempt."""

    hostname: str
    action: str
    attempt: int
    success: bool
    status: str
    message: str


@dataclass(frozen=True)
class IsolationResult:
    """Final result of the host isolation playbook."""

    hostname: str
    success: bool
    status: str
    attempts: int
    audit_log: tuple[IsolationAuditEntry, ...]


class HostIsolationPlaybook:
    """Execute host isolation through the configured EDR service."""

    def __init__(
        self,
        edr_service: EDRService | None = None,
        max_retries: int = 3,
    ) -> None:
        if max_retries < 1:
            raise ValueError("max_retries must be at least 1")

        self.edr_service = edr_service or EDRService()
        self.max_retries = max_retries

    def isolate(self, hostname: str) -> IsolationResult:
        """Attempt host isolation with bounded retry logic."""

        if not hostname.strip():
            raise ValueError("hostname must not be empty")

        audit_entries: list[IsolationAuditEntry] = []

        if not self.edr_service.authenticate():
            entry = IsolationAuditEntry(
                hostname=hostname,
                action="isolate_host",
                attempt=0,
                success=False,
                status="authentication_failed",
                message="EDR authentication failed before isolation.",
            )

            logger.error(entry.message)

            return IsolationResult(
                hostname=hostname,
                success=False,
                status="authentication_failed",
                attempts=0,
                audit_log=(entry,),
            )

        for attempt in range(1, self.max_retries + 1):
            try:
                success = self.edr_service.isolate_host(hostname)
                status = self.edr_service.get_isolation_status(hostname)

                if success and status == "isolated":
                    entry = IsolationAuditEntry(
                        hostname=hostname,
                        action="isolate_host",
                        attempt=attempt,
                        success=True,
                        status=status,
                        message="Host successfully isolated.",
                    )

                    audit_entries.append(entry)
                    logger.info(entry.message)

                    return IsolationResult(
                        hostname=hostname,
                        success=True,
                        status=status,
                        attempts=attempt,
                        audit_log=tuple(audit_entries),
                    )

                entry = IsolationAuditEntry(
                    hostname=hostname,
                    action="isolate_host",
                    attempt=attempt,
                    success=False,
                    status=status,
                    message="Host isolation attempt did not result in isolation.",
                )

            except Exception as exc:
                entry = IsolationAuditEntry(
                    hostname=hostname,
                    action="isolate_host",
                    attempt=attempt,
                    success=False,
                    status="error",
                    message=f"Host isolation attempt failed: {exc}",
                )

            audit_entries.append(entry)
            logger.warning(entry.message)

        final_status = audit_entries[-1].status

        return IsolationResult(
            hostname=hostname,
            success=False,
            status=final_status,
            attempts=self.max_retries,
            audit_log=tuple(audit_entries),
        )
