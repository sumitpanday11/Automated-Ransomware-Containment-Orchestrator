import json
from datetime import datetime, timezone

from app.database.database import IncidentDatabase
from app.database.states import IncidentState, VALID_TRANSITIONS


class IncidentRepository:
    def __init__(self, database: IncidentDatabase) -> None:
        self.database = database

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def create_incident(
        self,
        incident_id: str,
        alert_id: str | None = None,
        hostname: str | None = None,
        severity: str | None = None,
    ) -> None:
        if not incident_id.strip():
            raise ValueError("incident_id must not be empty")

        now = self._now()

        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO incidents (
                    incident_id, alert_id, hostname, severity,
                    status, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    alert_id,
                    hostname,
                    severity,
                    IncidentState.NEW.value,
                    now,
                    now,
                ),
            )

    def get_incident(self, incident_id: str) -> dict | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM incidents WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()

        return dict(row) if row else None

    def update_status(
        self,
        incident_id: str,
        new_status: IncidentState,
    ) -> None:
        incident = self.get_incident(incident_id)

        if incident is None:
            raise ValueError("incident not found")

        current_status = IncidentState(incident["status"])

        if current_status == new_status:
            return

        expected_status = VALID_TRANSITIONS.get(current_status)

        if expected_status != new_status:
            raise ValueError(
                f"invalid incident transition: "
                f"{current_status.value} -> {new_status.value}"
            )

        now = self._now()

        with self.database.connect() as connection:
            connection.execute(
                """
                UPDATE incidents
                SET status = ?, updated_at = ?
                WHERE incident_id = ?
                """,
                (new_status.value, now, incident_id),
            )

    def add_response_action(
        self,
        incident_id: str,
        action: str,
        actor: str,
        status: str,
        metadata: dict | None = None,
    ) -> None:
        if self.get_incident(incident_id) is None:
            raise ValueError("incident not found")

        if not action.strip():
            raise ValueError("action must not be empty")

        if not actor.strip():
            raise ValueError("actor must not be empty")

        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO response_actions (
                    incident_id, action, actor, status, timestamp, metadata
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    action,
                    actor,
                    status,
                    self._now(),
                    json.dumps(metadata or {}),
                ),
            )

    def add_evidence(
        self,
        evidence_id: str,
        incident_id: str,
        artifact_type: str,
        evidence_hash: str | None = None,
        storage_path: str | None = None,
        status: str = "stored",
    ) -> None:
        if self.get_incident(incident_id) is None:
            raise ValueError("incident not found")

        if not evidence_id.strip():
            raise ValueError("evidence_id must not be empty")

        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO evidence (
                    evidence_id, incident_id, artifact_type,
                    evidence_hash, storage_path, status, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evidence_id,
                    incident_id,
                    artifact_type,
                    evidence_hash,
                    storage_path,
                    status,
                    self._now(),
                ),
            )

    def add_audit_log(
        self,
        incident_id: str,
        actor: str,
        action: str,
        status: str,
        details: str | None = None,
    ) -> None:
        if self.get_incident(incident_id) is None:
            raise ValueError("incident not found")

        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO audit_logs (
                    incident_id, actor, action, status, details, timestamp
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    actor,
                    action,
                    status,
                    details,
                    self._now(),
                ),
            )

    def get_response_actions(self, incident_id: str) -> list[dict]:
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM response_actions
                WHERE incident_id = ?
                ORDER BY id
                """,
                (incident_id,),
            ).fetchall()

        return [dict(row) for row in rows]

    def get_evidence(self, incident_id: str) -> list[dict]:
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM evidence
                WHERE incident_id = ?
                ORDER BY created_at
                """,
                (incident_id,),
            ).fetchall()

        return [dict(row) for row in rows]

    def get_audit_logs(self, incident_id: str) -> list[dict]:
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM audit_logs
                WHERE incident_id = ?
                ORDER BY id
                """,
                (incident_id,),
            ).fetchall()

        return [dict(row) for row in rows]
