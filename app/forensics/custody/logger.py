from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class CustodyEvent:
    timestamp: datetime
    actor: str
    action: str
    evidence_id: str
    evidence_hash: str | None
    status: str
    metadata: dict[str, Any]


class ChainOfCustodyLogger:
    def __init__(self) -> None:
        self._events: list[CustodyEvent] = []

    def record(
        self,
        actor: str,
        action: str,
        evidence_id: str,
        evidence_hash: str | None,
        status: str,
        metadata: dict[str, Any] | None = None,
    ) -> CustodyEvent:
        if not actor.strip():
            raise ValueError("actor must not be empty")

        if not action.strip():
            raise ValueError("action must not be empty")

        if not evidence_id.strip():
            raise ValueError("evidence_id must not be empty")

        if not status.strip():
            raise ValueError("status must not be empty")

        event = CustodyEvent(
            timestamp=datetime.now(timezone.utc),
            actor=actor,
            action=action,
            evidence_id=evidence_id,
            evidence_hash=evidence_hash,
            status=status,
            metadata=metadata or {},
        )

        self._events.append(event)
        return event

    def events(self) -> list[CustodyEvent]:
        return list(self._events)

    def events_for_evidence(self, evidence_id: str) -> list[CustodyEvent]:
        if not evidence_id.strip():
            raise ValueError("evidence_id must not be empty")

        return [
            event
            for event in self._events
            if event.evidence_id == evidence_id
        ]

    def latest(self, evidence_id: str) -> CustodyEvent | None:
        events = self.events_for_evidence(evidence_id)
        return events[-1] if events else None
