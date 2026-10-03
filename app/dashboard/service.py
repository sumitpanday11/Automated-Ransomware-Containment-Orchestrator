from app.database.database import IncidentDatabase


class DashboardService:
    def __init__(self, database: IncidentDatabase) -> None:
        self.database = database

    def get_metrics(self) -> dict:
        with self.database.connect() as connection:
            total_incidents = connection.execute(
                "SELECT COUNT(*) FROM incidents"
            ).fetchone()[0]

            critical_incidents = connection.execute(
                """
                SELECT COUNT(*)
                FROM incidents
                WHERE UPPER(severity) = 'CRITICAL'
                """
            ).fetchone()[0]

            contained_incidents = connection.execute(
                """
                SELECT COUNT(*)
                FROM incidents
                WHERE UPPER(status) = 'CONTAINED'
                """
            ).fetchone()[0]

            failed_actions = connection.execute(
                """
                SELECT COUNT(*)
                FROM response_actions
                WHERE UPPER(status) = 'FAILED'
                """
            ).fetchone()[0]

            evidence_collected = connection.execute(
                """
                SELECT COUNT(*)
                FROM evidence
                """
            ).fetchone()[0]

            status_rows = connection.execute(
                """
                SELECT status, COUNT(*) AS count
                FROM incidents
                GROUP BY status
                ORDER BY status
                """
            ).fetchall()

        return {
            "total_incidents": total_incidents,
            "critical_incidents": critical_incidents,
            "contained_incidents": contained_incidents,
            "failed_actions": failed_actions,
            "evidence_collected": evidence_collected,
            "response_time": None,
            "current_incident_status": {
                row["status"]: row["count"]
                for row in status_rows
            },
        }