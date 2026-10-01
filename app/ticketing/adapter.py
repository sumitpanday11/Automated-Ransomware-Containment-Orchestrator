from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass
class IncidentTicket:
    incident_id: str
    host: str
    user: str
    severity: str
    detection: str
    actions_taken: list[str]
    evidence_location: Optional[str] = None


@dataclass
class TicketResult:
    success: bool
    ticket_id: Optional[str] = None
    provider: Optional[str] = None
    message: Optional[str] = None


class TicketingAdapter(ABC):

    @abstractmethod
    def create_ticket(self, ticket: IncidentTicket) -> TicketResult:
        raise NotImplementedError