import hashlib
import time

from app.detection.ransomware_engine import RansomwareDetectionEngine
from app.response.decision_engine import ResponseAction, build_response_decision
from app.response.risk_engine import RiskInput, calculate_risk
from app.response.isolation_playbook import HostIsolationPlaybook
from app.response.user_suspension_playbook import UserSuspensionPlaybook
from app.response.session_revocation_playbook import SessionRevocationPlaybook
from app.identity.service import IdentityService
from app.edr.service import EDRService
from app.forensics.collectors.mock import MockEvidenceCollector
from app.storage.s3.mock import MockS3EvidenceStorage
from app.storage.s3.config import S3StorageConfig
from app.storage.s3.workflow import EvidenceStorageWorkflow
from app.ticketing.mock import MockTicketingAdapter
from app.ticketing.service import IncidentTicketService
from app.notifications.mock import MockNotificationAdapter
from app.notifications.service import SOCNotificationService


def test_full_ransomware_response_simulation():
    """Safe Day 26 end-to-end ransomware simulation using mock providers."""

    total_start = time.perf_counter()

    alert = {
        "threat": "Ransomware",
        "detection_name": "Known Ransomware Detected",
        "behavior": "mass encryption",
        "activity": "mass file modification",
        "description": "Synthetic ransomware simulation alert",
        "process": "synthetic-ransomware.exe",
        "verdict": "malicious",
        "confidence": 0.98,
        "modified_file_count": 500,
    }

    hostname = "SIM-RANSOMWARE-HOST"
    username = "alice"

    # Detection
    detection_start = time.perf_counter()
    detection = RansomwareDetectionEngine().analyze(alert)
    detection_time = time.perf_counter() - detection_start

    assert detection.detected is True
    assert detection.detection_type == "known_ransomware"
    assert detection.confidence == 0.98
    assert detection.reasons

    # Risk
    risk = calculate_risk(
        RiskInput(
            ransomware_detected=True,
            encryption_activity=True,
            indicator_count=10,
            host_criticality=5,
            user_risk=5,
            detection_confidence=5,
        )
    )

    assert risk.score == 100
    assert risk.severity.value == "CRITICAL"

    # Decision
    decision_start = time.perf_counter()
    decision = build_response_decision(risk)
    decision_time = time.perf_counter() - decision_start

    assert decision.severity.value == "CRITICAL"
    assert decision.actions == (
        ResponseAction.ISOLATE_HOST,
        ResponseAction.SUSPEND_USER,
        ResponseAction.REVOKE_SESSIONS,
        ResponseAction.COLLECT_EVIDENCE,
    )

    # Mock containment providers
    edr_service = EDRService()
    identity_service = IdentityService(provider="mock")

    isolation = HostIsolationPlaybook(edr_service=edr_service)
    suspension = UserSuspensionPlaybook(identity_service=identity_service)
    revocation = SessionRevocationPlaybook(identity_service=identity_service)

    # Containment
    containment_start = time.perf_counter()

    isolation_result = isolation.isolate(hostname)
    assert isolation_result.success is True
    assert isolation_result.status == "isolated"

    suspension_result = suspension.suspend(username)
    assert suspension_result.success is True
    assert suspension_result.status == "suspended"

    revocation_result = revocation.revoke(username)
    assert revocation_result.success is True
    assert revocation_result.status == "revoked"
    assert revocation_result.revoked_sessions == 2
    assert revocation_result.tokens_revoked is True

    containment_time = time.perf_counter() - containment_start

    # Evidence collection
    evidence_start = time.perf_counter()

    collector = MockEvidenceCollector(
        collector_name="day26_ransomware_simulation",
        evidence_type_name="ransomware_simulation",
        data={
            "simulation": True,
            "threat": "ransomware",
            "process": "synthetic-ransomware.exe",
        },
    )

    evidence = collector.collect(hostname)

    assert evidence is not None
    assert evidence.data["simulation"] is True
    assert evidence.data["hostname"] == hostname

    evidence_bytes = str(evidence.data).encode("utf-8")

    # SHA-256
    evidence_hash = hashlib.sha256(evidence_bytes).hexdigest()

    assert len(evidence_hash) == 64
    assert evidence_hash == hashlib.sha256(evidence_bytes).hexdigest()

    # S3
    evidence_time = time.perf_counter() - evidence_start

    s3 = MockS3EvidenceStorage()

    storage = EvidenceStorageWorkflow(
        storage=s3,
        config=S3StorageConfig(
            bucket_name="day26-test-bucket",
            region="ap-south-1",
        ),
    )

    evidence_id = f"day26-{hostname.lower()}"

    storage_result = storage.store(
        evidence_id=evidence_id,
        artifact_type="ransomware_simulation",
        content=evidence_bytes,
        metadata={
            "sha256": evidence_hash,
            "simulation": "true",
            "hostname": hostname,
        },
    )

    assert storage_result.status == "stored"
    assert storage_result.upload is not None
    assert storage_result.upload.object_key in s3.objects

    # Mock Jira ticket
    ticket_adapter = MockTicketingAdapter()

    ticket_service = IncidentTicketService(
        adapter=ticket_adapter,
    )

    ticket_result = ticket_service.create_incident_ticket(
        incident_id="DAY26-SIMULATION-001",
        host=hostname,
        user=username,
        severity="CRITICAL",
        detection=detection.detection_type or "ransomware",
        actions_taken=[
            "host_isolation",
            "user_suspension",
            "session_revocation",
            "evidence_collection",
            "sha256_hash",
            "mock_s3_storage",
        ],
        evidence_location=storage_result.upload.object_key,
    )

    assert ticket_result.success is True
    assert ticket_result.ticket_id == "MOCK-SOC-0001"
    assert len(ticket_adapter.created_tickets) == 1

    # Mock SOC notification
    notification_adapter = MockNotificationAdapter()

    notification_service = SOCNotificationService(
        adapter=notification_adapter,
    )

    notification_result = notification_service.notify_incident(
        incident_id="DAY26-SIMULATION-001",
        host=hostname,
        user=username,
        threat="ransomware",
        severity="CRITICAL",
        status="CONTAINED",
        evidence_location=storage_result.upload.object_key,
    )

    assert notification_result.success is True
    assert notification_result.notification_id == "MOCK-SOC-NOTIFY-0001"
    assert len(notification_adapter.sent_notifications) == 1

    # Failed actions
    failed_actions = sum(
        [
            not isolation_result.success,
            not suspension_result.success,
            not revocation_result.success,
            storage_result.status != "stored",
            not ticket_result.success,
            not notification_result.success,
        ]
    )

    assert failed_actions == 0

    # Actual end-to-end response time
    total_response_time = time.perf_counter() - total_start

    metrics = {
        "detection_time_ms": round(detection_time * 1000, 3),
        "decision_time_ms": round(decision_time * 1000, 3),
        "containment_time_ms": round(containment_time * 1000, 3),
        "evidence_collection_time_ms": round(evidence_time * 1000, 3),
        "total_response_time_ms": round(total_response_time * 1000, 3),
        "failed_actions": failed_actions,
    }

    print("\n=== DAY 26 RANSOMWARE SIMULATION ===")
    print("Detection       :", detection.detection_type)
    print("Confidence      :", detection.confidence)
    print("Risk Score      :", risk.score)
    print("Severity        :", risk.severity.value)
    print("Host Isolation  :", isolation_result.status)
    print("User Suspension :", suspension_result.status)
    print("Sessions Revoked:", revocation_result.revoked_sessions)
    print("Tokens Revoked  :", revocation_result.tokens_revoked)
    print("Evidence        :", evidence_id)
    print("SHA-256         :", evidence_hash)
    print("S3              :", storage_result.status)
    print("Jira Ticket     :", ticket_result.ticket_id)
    print("SOC Notification:", notification_result.notification_id)
    print("Metrics         :", metrics)
    print("Failed Actions  :", failed_actions)
