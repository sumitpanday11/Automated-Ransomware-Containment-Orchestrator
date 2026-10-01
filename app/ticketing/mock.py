from .adapter import IncidentTicket, TicketResult, TicketingAdapter


class MockTicketingAdapter(TicketingAdapter):
    def __init__(self) -> None:
        self.created_tickets: list[IncidentTicket] = []
        self._counter = 0

    def create_ticket(self, ticket: IncidentTicket) -> TicketResult:
        self._counter += 1
        ticket_id = f"MOCK-SOC-{self._counter:04d}"

        self.created_tickets.append(ticket)

        return TicketResult(
            success=True,
            ticket_id=ticket_id,
            provider="mock",
            message="SOC incident ticket created successfully",
        )