from app.ticketing.adapter import IncidentTicket, TicketResult
from app.ticketing.mock import MockTicketingAdapter
from app.ticketing.service import IncidentTicketService


def test_critical_incident_creates_ticket():
    adapter = MockTicketingAdapter()
    service = IncidentTicketService(adapter)

    result = service.create_incident_ticket(
        incident_id="INC-001",
        host="HOST-01",
        user="alice",
        severity="CRITICAL",
        detection="Ransomware behavior detected",
        actions_taken=[
            "Host isolated",
            "User suspended",
            "Sessions revoked",
        ],
        evidence_location="s3://evidence/INC-001/",
    )

    assert result.success is True
    assert result.ticket_id == "MOCK-SOC-0001"
    assert result.provider == "mock"
    assert len(adapter.created_tickets) == 1

    ticket = adapter.created_tickets[0]
    assert ticket.incident_id == "INC-001"
    assert ticket.host == "HOST-01"
    assert ticket.user == "alice"
    assert ticket.severity == "CRITICAL"
    assert ticket.detection == "Ransomware behavior detected"
    assert "Host isolated" in ticket.actions_taken
    assert ticket.evidence_location == "s3://evidence/INC-001/"


def test_non_critical_incident_does_not_create_ticket():
    adapter = MockTicketingAdapter()
    service = IncidentTicketService(adapter)

    result = service.create_incident_ticket(
        incident_id="INC-002",
        host="HOST-02",
        user="bob",
        severity="HIGH",
        detection="Suspicious process",
        actions_taken=["Monitoring"],
    )

    assert result.success is False
    assert result.ticket_id is None
    assert "not CRITICAL" in result.message
    assert len(adapter.created_tickets) == 0


def test_ticket_contains_required_soc_information():
    adapter = MockTicketingAdapter()
    service = IncidentTicketService(adapter)

    service.create_incident_ticket(
        incident_id="INC-003",
        host="SERVER-01",
        user="admin",
        severity="critical",
        detection="Ransomware encryption activity",
        actions_taken=["Isolation", "Suspension"],
        evidence_location="/evidence/INC-003",
    )

    ticket = adapter.created_tickets[0]

    assert ticket.incident_id
    assert ticket.host
    assert ticket.user
    assert ticket.severity == "CRITICAL"
    assert ticket.detection
    assert ticket.actions_taken
    assert ticket.evidence_location


def test_mock_ticket_ids_are_unique():
    adapter = MockTicketingAdapter()
    service = IncidentTicketService(adapter)

    result1 = service.create_incident_ticket(
        "INC-101",
        "HOST-01",
        "alice",
        "CRITICAL",
        "Ransomware detected",
        ["Isolation"],
    )

    result2 = service.create_incident_ticket(
        "INC-102",
        "HOST-02",
        "bob",
        "CRITICAL",
        "Ransomware detected",
        ["Isolation"],
    )

    assert result1.ticket_id != result2.ticket_id
    assert result1.ticket_id == "MOCK-SOC-0001"
    assert result2.ticket_id == "MOCK-SOC-0002"