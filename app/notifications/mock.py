from .adapter import NotificationAdapter, NotificationResult, SOCNotification


class MockNotificationAdapter(NotificationAdapter):
    def __init__(self) -> None:
        self.sent_notifications: list[SOCNotification] = []
        self._counter = 0

    def send_notification(
        self,
        notification: SOCNotification,
    ) -> NotificationResult:
        self._counter += 1
        notification_id = f"MOCK-SOC-NOTIFY-{self._counter:04d}"

        self.sent_notifications.append(notification)

        return NotificationResult(
            success=True,
            notification_id=notification_id,
            provider="mock",
            message="SOC notification sent successfully",
        )