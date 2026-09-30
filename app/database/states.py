from enum import StrEnum


class IncidentState(StrEnum):
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    CONTAINING = "CONTAINING"
    CONTAINED = "CONTAINED"
    EVIDENCE_COLLECTED = "EVIDENCE_COLLECTED"
    RESOLVED = "RESOLVED"


VALID_TRANSITIONS: dict[IncidentState, IncidentState] = {
    IncidentState.NEW: IncidentState.INVESTIGATING,
    IncidentState.INVESTIGATING: IncidentState.CONTAINING,
    IncidentState.CONTAINING: IncidentState.CONTAINED,
    IncidentState.CONTAINED: IncidentState.EVIDENCE_COLLECTED,
    IncidentState.EVIDENCE_COLLECTED: IncidentState.RESOLVED,
}
