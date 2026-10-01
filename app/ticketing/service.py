from .adapter import IncidentTicket, TicketResult, TicketingAdapter
from .factory import get_ticketing_adapter


class IncidentTicketService:
    def __init__(self, adapter: TicketingAdapter | None = None) -> None:
        self.adapter = adapter or get_ticketing_adapter()

    def create_incident_ticket(
        self,
        incident_id: str,
        host: str,
        user: str,
        severity: str,
        detection: str,
        actions_taken: list[str],
        evidence_location: str | None = None,
    ) -> TicketResult:

        if severity.upper() != "CRITICAL":
            return TicketResult(
                success=False,
                provider="mock",
                message="Ticket creation skipped: incident is not CRITICAL",
            )

        ticket = IncidentTicket(
            incident_id=incident_id,
            host=host,
            user=user,
            severity=severity.upper(),
            detection=detection,
            actions_taken=actions_taken,
            evidence_location=evidence_location,
        )

        return self.adapter.create_ticket(ticket)