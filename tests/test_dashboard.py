from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.database.database import IncidentDatabase
from app.dashboard.service import DashboardService
from app.main import app


client = TestClient(app)


def test_dashboard_health():
    response = client.get("/api/dashboard/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy",
        "service": "incident-dashboard",
    }


def test_dashboard_metrics():
    response = client.get("/api/dashboard/metrics")

    assert response.status_code == 200

    data = response.json()

    assert "total_incidents" in data
    assert "critical_incidents" in data
    assert "contained_incidents" in data
    assert "failed_actions" in data
    assert "evidence_collected" in data
    assert "response_time" in data
    assert "current_incident_status" in data

    assert isinstance(data["total_incidents"], int)
    assert isinstance(data["critical_incidents"], int)
    assert isinstance(data["contained_incidents"], int)
    assert isinstance(data["failed_actions"], int)
    assert isinstance(data["evidence_collected"], int)
    assert data["response_time"] is None
    assert isinstance(data["current_incident_status"], dict)


def test_dashboard_metrics_with_incident_data(tmp_path):
    database = IncidentDatabase(str(tmp_path / "incidents.db"))

    now = datetime.now(timezone.utc).isoformat()

    with database.connect() as connection:
        connection.execute(
            """
            INSERT INTO incidents (
                incident_id,
                alert_id,
                hostname,
                severity,
                status,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "INC-DASH-001",
                "ALERT-DASH-001",
                "host-01",
                "CRITICAL",
                "CONTAINED",
                now,
                now,
            ),
        )

        connection.execute(
            """
            INSERT INTO incidents (
                incident_id,
                alert_id,
                hostname,
                severity,
                status,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "INC-DASH-002",
                "ALERT-DASH-002",
                "host-02",
                "HIGH",
                "INVESTIGATING",
                now,
                now,
            ),
        )

        connection.execute(
            """
            INSERT INTO response_actions (
                incident_id,
                action,
                actor,
                status,
                timestamp,
                metadata
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "INC-DASH-001",
                "host_isolation",
                "orchestrator",
                "FAILED",
                now,
                None,
            ),
        )

        connection.execute(
            """
            INSERT INTO evidence (
                evidence_id,
                incident_id,
                artifact_type,
                evidence_hash,
                storage_path,
                status,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "EVD-DASH-001",
                "INC-DASH-001",
                "event_logs",
                "abc123",
                "mock://evidence/EVD-DASH-001",
                "UPLOADED",
                now,
            ),
        )

    service = DashboardService(database)
    metrics = service.get_metrics()

    assert metrics["total_incidents"] == 2
    assert metrics["critical_incidents"] == 1
    assert metrics["contained_incidents"] == 1
    assert metrics["failed_actions"] == 1
    assert metrics["evidence_collected"] == 1
    assert metrics["response_time"] is None

    assert metrics["current_incident_status"] == {
        "CONTAINED": 1,
        "INVESTIGATING": 1,
    }