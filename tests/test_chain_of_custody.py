from app.forensics.custody.logger import ChainOfCustodyLogger
from app.forensics.custody.service import ChainOfCustodyService


def test_custody_event_records_required_fields() -> None:
    logger = ChainOfCustodyLogger()

    event = logger.record(
        actor="forensic-system",
        action="created",
        evidence_id="EV-001",
        evidence_hash=None,
        status="created",
    )

    assert event.actor == "forensic-system"
    assert event.action == "created"
    assert event.evidence_id == "EV-001"
    assert event.evidence_hash is None
    assert event.status == "created"
    assert event.timestamp.tzinfo is not None


def test_custody_event_preserves_hash() -> None:
    logger = ChainOfCustodyLogger()

    event = logger.record(
        actor="hash-service",
        action="hashed",
        evidence_id="EV-002",
        evidence_hash="abc123",
        status="hashed",
        metadata={"algorithm": "SHA-256"},
    )

    assert event.evidence_hash == "abc123"
    assert event.metadata["algorithm"] == "SHA-256"


def test_custody_events_are_tracked_in_order() -> None:
    logger = ChainOfCustodyLogger()

    logger.record("system", "created", "EV-003", None, "created")
    logger.record("collector", "collected", "EV-003", None, "collected")
    logger.record("hash-service", "hashed", "EV-003", "hash-003", "hashed")
    logger.record("s3-storage", "uploaded", "EV-003", "hash-003", "uploaded")

    events = logger.events()

    assert len(events) == 4
    assert [event.action for event in events] == [
        "created",
        "collected",
        "hashed",
        "uploaded",
    ]


def test_events_can_be_filtered_by_evidence_id() -> None:
    logger = ChainOfCustodyLogger()

    logger.record("system", "created", "EV-004", None, "created")
    logger.record("system", "created", "EV-005", None, "created")
    logger.record("collector", "collected", "EV-004", None, "collected")

    events = logger.events_for_evidence("EV-004")

    assert len(events) == 2
    assert all(event.evidence_id == "EV-004" for event in events)


def test_latest_event_is_returned() -> None:
    logger = ChainOfCustodyLogger()

    logger.record("system", "created", "EV-006", None, "created")
    logger.record("collector", "collected", "EV-006", None, "collected")
    logger.record("hash-service", "hashed", "EV-006", "hash-006", "hashed")

    latest = logger.latest("EV-006")

    assert latest is not None
    assert latest.action == "hashed"
    assert latest.evidence_hash == "hash-006"


def test_service_tracks_complete_chain_of_custody() -> None:
    service = ChainOfCustodyService()

    service.log_created("EV-007", "forensic-system")
    service.log_collected("EV-007", "host-collector")
    service.log_hashed("EV-007", "hash-service", "sha256-007")
    service.log_uploaded("EV-007", "s3-storage", "sha256-007")
    service.log_accessed("EV-007", "analyst", "sha256-007")
    service.log_analyzed("EV-007", "forensic-analyst", "sha256-007")

    events = service.logger.events_for_evidence("EV-007")

    assert [event.action for event in events] == [
        "created",
        "collected",
        "hashed",
        "uploaded",
        "accessed",
        "analyzed",
    ]
    assert all(event.evidence_id == "EV-007" for event in events)
    assert events[2].evidence_hash == "sha256-007"
    assert events[3].evidence_hash == "sha256-007"


def test_empty_actor_is_rejected() -> None:
    logger = ChainOfCustodyLogger()

    try:
        logger.record("", "created", "EV-008", None, "created")
    except ValueError as exc:
        assert str(exc) == "actor must not be empty"
    else:
        raise AssertionError("Expected ValueError")


def test_empty_action_is_rejected() -> None:
    logger = ChainOfCustodyLogger()

    try:
        logger.record("system", "", "EV-009", None, "created")
    except ValueError as exc:
        assert str(exc) == "action must not be empty"
    else:
        raise AssertionError("Expected ValueError")


def test_empty_evidence_id_is_rejected() -> None:
    logger = ChainOfCustodyLogger()

    try:
        logger.record("system", "created", "", None, "created")
    except ValueError as exc:
        assert str(exc) == "evidence_id must not be empty"
    else:
        raise AssertionError("Expected ValueError")


def test_empty_status_is_rejected() -> None:
    logger = ChainOfCustodyLogger()

    try:
        logger.record("system", "created", "EV-010", None, "")
    except ValueError as exc:
        assert str(exc) == "status must not be empty"
    else:
        raise AssertionError("Expected ValueError")
