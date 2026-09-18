from dataclasses import dataclass
from enum import Enum

from app.response.risk_engine import RiskResult, Severity


class ResponseAction(str, Enum):
    MONITOR = "monitor"
    LOG = "log"
    ISOLATE_HOST = "isolate_host"
    SUSPEND_USER = "suspend_user"
    REVOKE_SESSIONS = "revoke_sessions"
    COLLECT_EVIDENCE = "collect_evidence"


@dataclass(frozen=True)
class ResponseDecision:
    severity: Severity
    actions: tuple[ResponseAction, ...]
    reason: str


def decide_response(risk: RiskResult) -> ResponseDecision:
    """
    Convert a risk assessment into a deterministic response decision.

    This layer only decides which actions should be taken.
    It does not execute any real containment or account actions.
    """

    if risk.severity == Severity.CRITICAL:
        return ResponseDecision(
            severity=Severity.CRITICAL,
            actions=(
                ResponseAction.ISOLATE_HOST,
                ResponseAction.SUSPEND_USER,
                ResponseAction.REVOKE_SESSIONS,
                ResponseAction.COLLECT_EVIDENCE,
            ),
            reason="Critical ransomware risk requires immediate containment and evidence collection.",
        )

    if risk.severity == Severity.HIGH:
        return ResponseDecision(
            severity=Severity.HIGH,
            actions=(
                ResponseAction.ISOLATE_HOST,
                ResponseAction.REVOKE_SESSIONS,
                ResponseAction.COLLECT_EVIDENCE,
            ),
            reason="High ransomware risk requires host containment, session revocation, and evidence collection.",
        )

    if risk.severity == Severity.MEDIUM:
        return ResponseDecision(
            severity=Severity.MEDIUM,
            actions=(
                ResponseAction.MONITOR,
                ResponseAction.LOG,
                ResponseAction.COLLECT_EVIDENCE,
            ),
            reason="Medium risk requires monitoring, logging, and evidence collection.",
        )

    return ResponseDecision(
        severity=Severity.LOW,
        actions=(
            ResponseAction.MONITOR,
            ResponseAction.LOG,
        ),
        reason="Low risk requires monitoring and logging.",
    )


def build_response_decision(risk: RiskResult) -> ResponseDecision:
    """Compatibility wrapper for callers using an explicit builder name."""
    return decide_response(risk)
