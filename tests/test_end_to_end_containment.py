from uuid import uuid4

from app.detection.ransomware_engine import RansomwareDetectionEngine
from app.identity.service import IdentityService
from app.models.incident import (
    Incident,
    IncidentStatus,
    Severity as IncidentSeverity,
)
from app.response.decision_engine import ResponseAction, decide_response
from app.response.isolation_playbook import HostIsolationPlaybook
from app.response.risk_engine import Severity, RiskInput, calculate_risk
from app.response.session_revocation_playbook import SessionRevocationPlaybook
from app.response.user_suspension_playbook import UserSuspensionPlaybook
from app.edr.service import EDRService


def build_ransomware_alert() -> dict:
    return {
        "hostname": "workstation-01",
        "username": "alice",
        "threat": "ransomware",
        "detection_name": "known ransomware detected",
        "activity": "mass file modification",
        "modified_file_count": 500,
        "confidence": 0.98,
    }


def build_critical_risk(alert: dict):
    detection = RansomwareDetectionEngine().analyze(alert)

    assert detection.detected is True

    risk = calculate_risk(
        RiskInput(
            ransomware_detected=detection.detected,
            encryption_activity=True,
            indicator_count=10,
            host_criticality=5,
            user_risk=5,
            detection_confidence=5,
        )
    )

    return detection, risk


def test_complete_containment_playbook():
    alert = build_ransomware_alert()

    detection, risk = build_critical_risk(alert)

    assert detection.detected is True
    assert risk.severity == Severity.CRITICAL

    decision = decide_response(risk)

    assert decision.severity == Severity.CRITICAL
    assert ResponseAction.ISOLATE_HOST in decision.actions
    assert ResponseAction.SUSPEND_USER in decision.actions
    assert ResponseAction.REVOKE_SESSIONS in decision.actions

    incident = Incident(
        alert_id=uuid4(),
        hostname=alert["hostname"],
        username=alert["username"],
        severity=IncidentSeverity.CRITICAL,
        threat_type="ransomware",
    )

    edr_service = EDRService()
    identity_service = IdentityService()

    isolation = HostIsolationPlaybook(
        edr_service=edr_service
    ).isolate(incident.hostname)

    assert isolation.success is True
    assert isolation.status == "isolated"

    suspension = UserSuspensionPlaybook(
        identity_service=identity_service
    ).suspend(incident.username)

    assert suspension.success is True
    assert suspension.status == "suspended"

    revocation = SessionRevocationPlaybook(
        identity_service=identity_service
    ).revoke(incident.username)

    assert revocation.success is True
    assert revocation.status == "revoked"
    assert revocation.tokens_revoked is True

    incident.status = IncidentStatus.CONTAINED

    assert incident.status == IncidentStatus.CONTAINED


def test_containment_stops_when_host_isolation_fails():
    alert = build_ransomware_alert()

    _, risk = build_critical_risk(alert)

    assert risk.severity == Severity.CRITICAL

    incident = Incident(
        alert_id=uuid4(),
        hostname=alert["hostname"],
        username=alert["username"],
        severity=IncidentSeverity.CRITICAL,
        threat_type="ransomware",
    )

    class FailingEDR:
        def authenticate(self) -> bool:
            return True

        def isolate_host(self, hostname: str) -> bool:
            return False

        def get_isolation_status(self, hostname: str) -> str:
            return "not_isolated"

    edr_service = EDRService()
    edr_service.provider = FailingEDR()

    isolation = HostIsolationPlaybook(
        edr_service=edr_service,
        max_retries=2,
    ).isolate(incident.hostname)

    assert isolation.success is False
    assert isolation.status == "not_isolated"
    assert isolation.attempts == 2

    assert incident.status == IncidentStatus.OPEN


def test_containment_stops_when_user_suspension_fails():
    alert = build_ransomware_alert()

    _, risk = build_critical_risk(alert)

    assert risk.severity == Severity.CRITICAL

    incident = Incident(
        alert_id=uuid4(),
        hostname=alert["hostname"],
        username=alert["username"],
        severity=IncidentSeverity.CRITICAL,
        threat_type="ransomware",
    )

    edr_service = EDRService()

    isolation = HostIsolationPlaybook(
        edr_service=edr_service
    ).isolate(incident.hostname)

    assert isolation.success is True

    class FailingIdentity:
        def authenticate(self) -> bool:
            return True

        def lookup_user(self, username: str):
            return {"username": username, "status": "active"}

        def suspend_user(self, username: str) -> bool:
            return False

        def list_active_sessions(self, username: str) -> list[dict]:
            return [{"session_id": "test-session", "status": "active"}]

        def revoke_session(self, username: str, session_id: str) -> bool:
            return True

        def revoke_tokens(self, username: str) -> bool:
            return True

    identity_service = IdentityService(
        identity_provider=FailingIdentity()
    )

    suspension = UserSuspensionPlaybook(
        identity_service=identity_service
    ).suspend(incident.username)

    assert suspension.success is False
    assert suspension.status == "suspension_failed"

    assert incident.status == IncidentStatus.OPEN


def test_containment_stops_when_token_revocation_fails():
    alert = build_ransomware_alert()

    _, risk = build_critical_risk(alert)

    assert risk.severity == Severity.CRITICAL

    incident = Incident(
        alert_id=uuid4(),
        hostname=alert["hostname"],
        username=alert["username"],
        severity=IncidentSeverity.CRITICAL,
        threat_type="ransomware",
    )

    edr_service = EDRService()

    isolation = HostIsolationPlaybook(
        edr_service=edr_service
    ).isolate(incident.hostname)

    assert isolation.success is True

    class TokenFailingIdentity:
        def __init__(self):
            self.sessions_revoked = []

        def authenticate(self) -> bool:
            return True

        def lookup_user(self, username: str):
            return {"username": username, "status": "active"}

        def suspend_user(self, username: str) -> bool:
            return True

        def list_active_sessions(self, username: str) -> list[dict]:
            return [{"session_id": "test-session", "status": "active"}]

        def revoke_session(self, username: str, session_id: str) -> bool:
            self.sessions_revoked.append(session_id)
            return True

        def revoke_tokens(self, username: str) -> bool:
            return False

    identity_service = IdentityService(
        identity_provider=TokenFailingIdentity()
    )

    suspension = UserSuspensionPlaybook(
        identity_service=identity_service
    ).suspend(incident.username)

    assert suspension.success is True
    assert suspension.status == "suspended"

    revocation = SessionRevocationPlaybook(
        identity_service=identity_service
    ).revoke(incident.username)

    assert revocation.success is False
    assert revocation.status == "partial_revocation"
    assert revocation.tokens_revoked is False

    assert incident.status == IncidentStatus.OPEN