from app.notifications.mock import MockNotificationAdapter
from app.notifications.adapter import NotificationResult
from app.notifications.service import SOCNotificationService


def test_critical_incident_sends_notification():
    adapter = MockNotificationAdapter()
    service = SOCNotificationService(adapter)

    result = service.notify_incident(
        incident_id="INC-001",
        host="WORKSTATION-01",
        user="test-user",
        threat="Ransomware",
        severity="CRITICAL",
        status="CONTAINED",
        evidence_location="s3://evidence/INC-001/",
    )

    assert result.success is True
    assert result.notification_id == "MOCK-SOC-NOTIFY-0001"
    assert result.provider == "mock"
    assert len(adapter.sent_notifications) == 1

    notification = adapter.sent_notifications[0]
    assert notification.incident_id == "INC-001"
    assert notification.host == "WORKSTATION-01"
    assert notification.user == "test-user"
    assert notification.threat == "Ransomware"
    assert notification.severity == "CRITICAL"
    assert notification.status == "CONTAINED"
    assert notification.evidence_location == "s3://evidence/INC-001/"


def test_non_critical_incident_does_not_send_notification():
    adapter = MockNotificationAdapter()
    service = SOCNotificationService(adapter)

    result = service.notify_incident(
        incident_id="INC-002",
        host="WORKSTATION-02",
        user="alice",
        threat="Suspicious activity",
        severity="HIGH",
        status="INVESTIGATING",
    )

    assert result.success is False
    assert result.notification_id is None
    assert "not CRITICAL" in result.message
    assert len(adapter.sent_notifications) == 0


def test_notification_contains_required_soc_information():
    adapter = MockNotificationAdapter()
    service = SOCNotificationService(adapter)

    service.notify_incident(
        incident_id="INC-003",
        host="SERVER-01",
        user="admin",
        threat="Ransomware",
        severity="critical",
        status="contained",
        evidence_location="s3://evidence/INC-003/",
    )

    notification = adapter.sent_notifications[0]

    assert notification.incident_id
    assert notification.host
    assert notification.user
    assert notification.threat
    assert notification.severity == "CRITICAL"
    assert notification.status == "CONTAINED"
    assert notification.evidence_location


def test_notification_ids_are_unique():
    adapter = MockNotificationAdapter()
    service = SOCNotificationService(adapter)

    result1 = service.notify_incident(
        "INC-101",
        "HOST-01",
        "alice",
        "Ransomware",
        "CRITICAL",
        "CONTAINED",
    )

    result2 = service.notify_incident(
        "INC-102",
        "HOST-02",
        "bob",
        "Ransomware",
        "CRITICAL",
        "CONTAINED",
    )

    assert result1.notification_id != result2.notification_id
    assert result1.notification_id == "MOCK-SOC-NOTIFY-0001"
    assert result2.notification_id == "MOCK-SOC-NOTIFY-0002"
def test_notification_failure_is_returned(monkeypatch):
    adapter = MockNotificationAdapter()
    service = SOCNotificationService(adapter)

    def fail_notification(notification):
        return NotificationResult(
            success=False,
            notification_id=None,
            provider="mock",
            message="SOC notification failed",
        )

    monkeypatch.setattr(
        adapter,
        "send_notification",
        fail_notification,
    )

    result = service.notify_incident(
        incident_id="INC-004",
        host="WORKSTATION-04",
        user="alice",
        threat="Ransomware",
        severity="CRITICAL",
        status="CONTAINED",
    )

    assert result.success is False
    assert result.notification_id is None
    assert result.provider == "mock"
    assert result.message == "SOC notification failed"

