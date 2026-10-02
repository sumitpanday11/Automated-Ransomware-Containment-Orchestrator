from .adapter import NotificationAdapter, NotificationResult, SOCNotification
from .factory import get_notification_adapter


class SOCNotificationService:
    def __init__(
        self,
        adapter: NotificationAdapter | None = None,
    ) -> None:
        self.adapter = adapter or get_notification_adapter()

    def notify_incident(
        self,
        incident_id: str,
        host: str,
        user: str,
        threat: str,
        severity: str,
        status: str,
        evidence_location: str | None = None,
    ) -> NotificationResult:

        if severity.upper() != "CRITICAL":
            return NotificationResult(
                success=False,
                provider="mock",
                message="Notification skipped: incident is not CRITICAL",
            )

        notification = SOCNotification(
            incident_id=incident_id,
            host=host,
            user=user,
            threat=threat,
            severity=severity.upper(),
            status=status.upper(),
            evidence_location=evidence_location,
        )

        return self.adapter.send_notification(notification)