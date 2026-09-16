from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskInput(BaseModel):
    ransomware_detected: bool = False
    encryption_activity: bool = False
    indicator_count: int = Field(default=0, ge=0)
    host_criticality: int = Field(default=1, ge=1, le=5)
    user_risk: int = Field(default=1, ge=1, le=5)
    detection_confidence: int = Field(default=1, ge=1, le=5)


class RiskResult(BaseModel):
    score: int
    severity: Severity
    reasons: list[str]


def calculate_risk(data: RiskInput) -> RiskResult:
    score = 0
    reasons: list[str] = []

    # Ransomware detection
    if data.ransomware_detected:
        score += 30
        reasons.append("Ransomware detection")

    # Encryption activity
    if data.encryption_activity:
        score += 25
        reasons.append("Encryption activity")

    # Number of indicators
    if data.indicator_count >= 10:
        score += 20
        reasons.append("High indicator count")
    elif data.indicator_count >= 5:
        score += 10
        reasons.append("Multiple indicators")
    elif data.indicator_count >= 1:
        score += 5
        reasons.append("Threat indicators present")

    # Host criticality
    host_score = data.host_criticality * 3
    score += host_score
    if data.host_criticality >= 4:
        reasons.append("Critical host")

    # User risk
    user_score = data.user_risk * 2
    score += user_score
    if data.user_risk >= 4:
        reasons.append("High-risk user")

    # Detection confidence
    confidence_score = data.detection_confidence * 2
    score += confidence_score

    if data.detection_confidence >= 4:
        reasons.append("High detection confidence")

    # Cap score at 100
    score = min(score, 100)

    # Severity classification
    if score >= 80:
        severity = Severity.CRITICAL
    elif score >= 60:
        severity = Severity.HIGH
    elif score >= 30:
        severity = Severity.MEDIUM
    else:
        severity = Severity.LOW

    return RiskResult(
        score=score,
        severity=severity,
        reasons=reasons,
    )