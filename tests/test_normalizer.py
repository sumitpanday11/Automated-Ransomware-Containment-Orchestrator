from uuid import UUID

import pytest

from app.edr.normalizer import normalize_alert, to_incident
from app.models.incident import Severity


def test_crowdstrike_alert_normalization():
    payload = {
        "composite_id": "CS-001",
        "severity": "critical",
        "type": "ransomware_behavior",
        "device": {
            "hostname": "WORKSTATION-01",
            "local_ip": "192.168.1.50",
        },
        "user": {
            "name": "admin",
        },
        "process": {
            "name": "ransomware.exe",
            "sha256": "abc123",
        },
        "threat": {
            "name": "Ransomware",
        },
        "indicators": [
            "file_hash:abc123",
            "ip:192.168.1.50",
        ],
        "description": "Ransomware behavior detected",
    }

    alert = normalize_alert(payload, "crowdstrike")

    assert isinstance(alert.alert_id, UUID)
    assert alert.severity == Severity.CRITICAL
    assert alert.hostname == "WORKSTATION-01"
    assert alert.username == "admin"
    assert alert.process_name == "ransomware.exe"


def test_defender_alert_normalization():
    payload = {
        "id": "DEF-001",
        "severity": "high",
        "category": "ransomware_detection",
        "device": {
            "deviceName": "SERVER-01",
            "ipAddress": "10.0.0.25",
        },
        "user": {
            "userName": "admin",
        },
        "process": {
            "fileName": "malware.exe",
            "sha256": "def456",
        },
        "threat": {
            "name": "Ransomware",
        },
        "indicators": [
            "file_hash:def456",
        ],
        "description": "Suspicious encryption activity",
    }

    alert = normalize_alert(payload, "defender")

    assert alert.severity == Severity.HIGH
    assert alert.hostname == "SERVER-01"
    assert alert.username == "admin"
    assert alert.process_name == "malware.exe"


def test_normalized_alert_converts_to_incident():
    payload = {
        "composite_id": "CS-002",
        "severity": "critical",
        "type": "ransomware_behavior",
        "device": {
            "hostname": "HOST-01",
            "local_ip": "10.0.0.10",
        },
        "user": {
            "name": "admin",
        },
        "process": {
            "name": "evil.exe",
            "sha256": "hash123",
        },
        "threat": {
            "name": "Ransomware",
        },
    }

    alert = normalize_alert(payload, "crowdstrike")
    incident = to_incident(alert)

    assert isinstance(incident.incident_id, UUID)
    assert incident.alert_id == alert.alert_id
    assert incident.hostname == "HOST-01"
    assert incident.username == "admin"
    assert incident.severity == Severity.CRITICAL
    assert incident.threat_type == "Ransomware"


def test_invalid_crowdstrike_payload_rejected():
    payload = {
        "composite_id": "CS-003",
        "severity": "critical",
    }

    with pytest.raises(ValueError):
        normalize_alert(payload, "crowdstrike")


def test_invalid_defender_payload_rejected():
    payload = {
        "id": "DEF-002",
        "severity": "high",
    }

    with pytest.raises(ValueError):
        normalize_alert(payload, "defender")


def test_unsupported_provider_rejected():
    with pytest.raises(ValueError):
        normalize_alert({}, "unknown-edr")
