from app.response.decision_engine import (
    ResponseAction,
    build_response_decision,
    decide_response,
)
from app.response.risk_engine import RiskResult, Severity


def make_risk(severity: Severity) -> RiskResult:
    return RiskResult(
        score=90,
        severity=severity,
        reasons=["test risk"],
    )


def test_low_risk_returns_monitor_and_log():
    result = decide_response(make_risk(Severity.LOW))

    assert result.severity == Severity.LOW
    assert result.actions == (
        ResponseAction.MONITOR,
        ResponseAction.LOG,
    )


def test_medium_risk_returns_monitor_log_and_evidence():
    result = decide_response(make_risk(Severity.MEDIUM))

    assert result.severity == Severity.MEDIUM
    assert result.actions == (
        ResponseAction.MONITOR,
        ResponseAction.LOG,
        ResponseAction.COLLECT_EVIDENCE,
    )


def test_high_risk_returns_containment_actions():
    result = decide_response(make_risk(Severity.HIGH))

    assert result.severity == Severity.HIGH
    assert result.actions == (
        ResponseAction.ISOLATE_HOST,
        ResponseAction.REVOKE_SESSIONS,
        ResponseAction.COLLECT_EVIDENCE,
    )


def test_critical_risk_returns_full_containment_actions():
    result = decide_response(make_risk(Severity.CRITICAL))

    assert result.severity == Severity.CRITICAL
    assert result.actions == (
        ResponseAction.ISOLATE_HOST,
        ResponseAction.SUSPEND_USER,
        ResponseAction.REVOKE_SESSIONS,
        ResponseAction.COLLECT_EVIDENCE,
    )


def test_response_reason_is_present():
    result = decide_response(make_risk(Severity.CRITICAL))

    assert result.reason
    assert "Critical" in result.reason


def test_builder_returns_same_decision_type():
    result = build_response_decision(make_risk(Severity.HIGH))

    assert result.severity == Severity.HIGH
    assert ResponseAction.ISOLATE_HOST in result.actions
