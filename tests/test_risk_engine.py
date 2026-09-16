from app.response.risk_engine import (
    RiskInput,
    Severity,
    calculate_risk,
)


def test_low_risk():
    result = calculate_risk(
        RiskInput(
            indicator_count=0,
            host_criticality=1,
            user_risk=1,
            detection_confidence=1,
        )
    )

    assert result.severity == Severity.LOW
    assert result.score < 30


def test_medium_risk():
    result = calculate_risk(
        RiskInput(
            ransomware_detected=True,
            indicator_count=1,
            host_criticality=1,
            user_risk=1,
            detection_confidence=1,
        )
    )

    assert result.severity == Severity.MEDIUM
    assert 30 <= result.score < 60


def test_high_risk():
    result = calculate_risk(
        RiskInput(
            ransomware_detected=True,
            indicator_count=5,
            host_criticality=3,
            user_risk=3,
            detection_confidence=3,
        )
    )

    assert result.severity == Severity.HIGH
    assert 60 <= result.score < 80


def test_critical_ransomware():
    result = calculate_risk(
        RiskInput(
            ransomware_detected=True,
            encryption_activity=True,
            indicator_count=10,
            host_criticality=5,
            user_risk=5,
            detection_confidence=5,
        )
    )

    assert result.severity == Severity.CRITICAL
    assert result.score == 100


def test_reasons_are_generated():
    result = calculate_risk(
        RiskInput(
            ransomware_detected=True,
            encryption_activity=True,
            indicator_count=10,
            host_criticality=5,
            user_risk=5,
            detection_confidence=5,
        )
    )

    assert "Ransomware detection" in result.reasons
    assert "Encryption activity" in result.reasons
    assert "High indicator count" in result.reasons
    assert "Critical host" in result.reasons
    assert "High-risk user" in result.reasons
    assert "High detection confidence" in result.reasons