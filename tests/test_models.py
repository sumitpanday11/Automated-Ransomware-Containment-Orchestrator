from uuid import UUID

from app.models.alert import Alert
from app.models.incident import (
    Incident,
    IncidentStatus,
    Severity,
)


def test_incident_model_defaults():
    incident = Incident(
        alert_id=UUID("12345678-1234-5678-1234-567812345678"),
        hostname="WORKSTATION-01",
        username="admin",
        source_ip="192.168.1.50",
        process_name="malware.exe",
        process_hash="abc123",
        severity=Severity.CRITICAL,
        threat_type="ransomware",
        indicators=["file_hash:abc123", "ip:192.168.1.50"],
    )

    assert isinstance(incident.incident_id, UUID)
    assert incident.hostname == "WORKSTATION-01"
    assert incident.username == "admin"
    assert incident.severity == Severity.CRITICAL
    assert incident.status == IncidentStatus.OPEN
    assert len(incident.indicators) == 2
    assert incident.created_at is not None
    assert incident.updated_at is not None


def test_alert_model():
    alert = Alert(
        alert_type="ransomware_detection",
        description="Suspicious file encryption activity detected",
        severity=Severity.HIGH,
        hostname="SERVER-01",
        username="admin",
        source_ip="10.0.0.25",
        indicators=["file_extension:.encrypted"],
    )

    assert isinstance(alert.alert_id, UUID)
    assert alert.alert_type == "ransomware_detection"
    assert alert.severity == Severity.HIGH
    assert alert.hostname == "SERVER-01"
    assert len(alert.indicators) == 1
    assert alert.created_at is not None


def test_incident_status_values():
    assert IncidentStatus.OPEN.value == "open"
    assert IncidentStatus.INVESTIGATING.value == "investigating"
    assert IncidentStatus.CONTAINED.value == "contained"
    assert IncidentStatus.RESOLVED.value == "resolved"
    assert IncidentStatus.CLOSED.value == "closed"
