import os

from fastapi.testclient import TestClient

from app.main import app


os.environ["EDR_API_KEY"] = "test-integration-key"

client = TestClient(app)

HEADERS = {
    "X-EDR-API-Key": "test-integration-key",
    "X-EDR-Provider": "crowdstrike",
}


def valid_crowdstrike_alert():
    return {
        "composite_id": "cs-integration-001",
        "severity": "high",
        "type": "ransomware_detection",
        "device": {
            "hostname": "WORKSTATION-01",
            "local_ip": "192.168.1.50",
        },
        "user": {
            "name": "admin",
        },
        "process": {
            "name": "malware.exe",
            "sha256": "abc123",
        },
        "threat": {
            "name": "ransomware",
        },
        "indicators": [
            "file_hash:abc123",
            "ip:192.168.1.50",
        ],
        "description": "Suspicious ransomware activity detected",
    }


def test_valid_alert_ingestion():
    response = client.post(
        "/webhook/edr",
        json=valid_crowdstrike_alert(),
        headers=HEADERS,
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "accepted"
    assert data["provider"] == "crowdstrike"
    assert data["incident"]["hostname"] == "WORKSTATION-01"
    assert data["incident"]["username"] == "admin"
    assert data["incident"]["severity"] == "high"
    assert data["incident"]["process_name"] == "malware.exe"


def test_invalid_alert():
    payload = valid_crowdstrike_alert()
    payload["severity"] = "invalid-severity"

    response = client.post(
        "/webhook/edr",
        json=payload,
        headers=HEADERS,
    )

    assert response.status_code == 422


def test_missing_hostname():
    payload = valid_crowdstrike_alert()
    del payload["device"]["hostname"]

    response = client.post(
        "/webhook/edr",
        json=payload,
        headers=HEADERS,
    )

    assert response.status_code == 422


def test_missing_severity():
    payload = valid_crowdstrike_alert()
    del payload["severity"]

    response = client.post(
        "/webhook/edr",
        json=payload,
        headers=HEADERS,
    )

    assert response.status_code == 422


def test_malformed_json():
    response = client.post(
        "/webhook/edr",
        content=b'{"composite_id": "broken"',
        headers={
            **HEADERS,
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 422


def test_duplicate_alert_is_accepted_without_duplicate_handling():
    payload = valid_crowdstrike_alert()

    first = client.post(
        "/webhook/edr",
        json=payload,
        headers=HEADERS,
    )

    second = client.post(
        "/webhook/edr",
        json=payload,
        headers=HEADERS,
    )

    assert first.status_code == 200
    assert second.status_code == 200

    first_data = first.json()
    second_data = second.json()

    assert first_data["alert_id"] == second_data["alert_id"]
    assert first_data["incident"]["alert_id"] == second_data["incident"]["alert_id"]
