import sqlite3

import pytest

from app.database.database import IncidentDatabase
from app.database.repository import IncidentRepository
from app.database.states import IncidentState


@pytest.fixture
def repository(tmp_path):
    database = IncidentDatabase(str(tmp_path / "incidents.db"))
    return IncidentRepository(database)


def test_database_creates_required_tables(repository) -> None:
    with repository.database.connect() as connection:
        tables = {
            row["name"]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }

    assert {
        "incidents",
        "response_actions",
        "evidence",
        "audit_logs",
    }.issubset(tables)


def test_incident_is_persisted(repository) -> None:
    repository.create_incident(
        incident_id="INC-001",
        alert_id="ALT-001",
        hostname="host-01",
        severity="CRITICAL",
    )

    incident = repository.get_incident("INC-001")

    assert incident is not None
    assert incident["alert_id"] == "ALT-001"
    assert incident["hostname"] == "host-01"
    assert incident["severity"] == "CRITICAL"
    assert incident["status"] == "NEW"


def test_incident_follows_state_machine(repository) -> None:
    repository.create_incident("INC-002")

    for state in (
        IncidentState.INVESTIGATING,
        IncidentState.CONTAINING,
        IncidentState.CONTAINED,
        IncidentState.EVIDENCE_COLLECTED,
        IncidentState.RESOLVED,
    ):
        repository.update_status("INC-002", state)

    incident = repository.get_incident("INC-002")

    assert incident is not None
    assert incident["status"] == "RESOLVED"


def test_invalid_state_transition_is_rejected(repository) -> None:
    repository.create_incident("INC-003")

    with pytest.raises(ValueError, match="invalid incident transition"):
        repository.update_status(
            "INC-003",
            IncidentState.CONTAINED,
        )


def test_response_action_is_persisted(repository) -> None:
    repository.create_incident("INC-004")

    repository.add_response_action(
        incident_id="INC-004",
        action="host_isolation",
        actor="containment-engine",
        status="success",
        metadata={"hostname": "host-04"},
    )

    actions = repository.get_response_actions("INC-004")

    assert len(actions) == 1
    assert actions[0]["action"] == "host_isolation"
    assert actions[0]["actor"] == "containment-engine"
    assert actions[0]["status"] == "success"


def test_evidence_is_persisted(repository) -> None:
    repository.create_incident("INC-005")

    repository.add_evidence(
        evidence_id="EV-005",
        incident_id="INC-005",
        artifact_type="memory",
        evidence_hash="sha256-005",
        storage_path="evidence/memory/EV-005.raw",
    )

    evidence = repository.get_evidence("INC-005")

    assert len(evidence) == 1
    assert evidence[0]["evidence_id"] == "EV-005"
    assert evidence[0]["artifact_type"] == "memory"
    assert evidence[0]["evidence_hash"] == "sha256-005"


def test_audit_log_is_persisted(repository) -> None:
    repository.create_incident("INC-006")

    repository.add_audit_log(
        incident_id="INC-006",
        actor="soc-analyst",
        action="incident_created",
        status="success",
        details="Incident opened for investigation",
    )

    logs = repository.get_audit_logs("INC-006")

    assert len(logs) == 1
    assert logs[0]["actor"] == "soc-analyst"
    assert logs[0]["action"] == "incident_created"
    assert logs[0]["details"] == "Incident opened for investigation"


def test_database_persists_between_repository_instances(tmp_path) -> None:
    database_path = str(tmp_path / "persistent.db")

    first = IncidentRepository(IncidentDatabase(database_path))
    first.create_incident(
        incident_id="INC-007",
        severity="HIGH",
    )

    second = IncidentRepository(IncidentDatabase(database_path))
    incident = second.get_incident("INC-007")

    assert incident is not None
    assert incident["severity"] == "HIGH"


def test_missing_incident_is_rejected_for_actions(repository) -> None:
    with pytest.raises(ValueError, match="incident not found"):
        repository.add_response_action(
            incident_id="MISSING",
            action="isolate",
            actor="system",
            status="success",
        )


def test_missing_incident_is_rejected_for_evidence(repository) -> None:
    with pytest.raises(ValueError, match="incident not found"):
        repository.add_evidence(
            evidence_id="EV-008",
            incident_id="MISSING",
            artifact_type="memory",
        )


def test_missing_incident_is_rejected_for_audit_log(repository) -> None:
    with pytest.raises(ValueError, match="incident not found"):
        repository.add_audit_log(
            incident_id="MISSING",
            actor="system",
            action="test",
            status="success",
        )
