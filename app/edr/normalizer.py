from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import BaseModel, Field, ValidationError

from app.models.incident import Incident, Severity


class NormalizedEDRAlert(BaseModel):
    alert_id: UUID
    severity: Severity
    alert_type: str
    hostname: str
    username: str | None = None
    source_ip: str | None = None
    process_name: str | None = None
    process_hash: str | None = None
    threat_type: str = "unknown"
    indicators: list[str] = Field(default_factory=list)
    description: str = ""


def _alert_uuid(provider: str, alert_id: str) -> UUID:
    return uuid5(
        NAMESPACE_URL,
        f"ransomware-orchestrator:{provider}:{alert_id}",
    )


def _severity(value: Any) -> Severity:
    if not isinstance(value, str):
        raise ValueError("severity must be a string")

    value = value.lower().strip()

    mapping = {
        "informational": Severity.LOW,
        "info": Severity.LOW,
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "moderate": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL,
    }

    if value not in mapping:
        raise ValueError(f"Unsupported severity: {value}")

    return mapping[value]


def normalize_crowdstrike(
    payload: dict[str, Any],
) -> NormalizedEDRAlert:
    return NormalizedEDRAlert(
        alert_id=_alert_uuid(
            "crowdstrike",
            payload["composite_id"],
        ),
        severity=_severity(payload["severity"]),
        alert_type=payload["type"],
        hostname=payload["device"]["hostname"],
        username=payload.get("user", {}).get("name"),
        source_ip=payload["device"].get("local_ip"),
        process_name=payload.get("process", {}).get("name"),
        process_hash=payload.get("process", {}).get("sha256"),
        threat_type=payload.get("threat", {}).get("name", "unknown"),
        indicators=payload.get("indicators", []),
        description=payload.get("description", ""),
    )


def normalize_defender(
    payload: dict[str, Any],
) -> NormalizedEDRAlert:
    return NormalizedEDRAlert(
        alert_id=_alert_uuid(
            "defender",
            payload["id"],
        ),
        severity=_severity(payload["severity"]),
        alert_type=payload["category"],
        hostname=payload["device"]["deviceName"],
        username=payload.get("user", {}).get("userName"),
        source_ip=payload["device"].get("ipAddress"),
        process_name=payload.get("process", {}).get("fileName"),
        process_hash=payload.get("process", {}).get("sha256"),
        threat_type=payload.get("threat", {}).get("name", "unknown"),
        indicators=payload.get("indicators", []),
        description=payload.get("description", ""),
    )


def normalize_alert(
    payload: dict[str, Any],
    provider: str,
) -> NormalizedEDRAlert:
    provider = provider.lower().strip()

    try:
        if provider == "crowdstrike":
            return normalize_crowdstrike(payload)

        if provider in {"defender", "microsoft_defender"}:
            return normalize_defender(payload)

    except (KeyError, TypeError, ValueError, ValidationError) as exc:
        raise ValueError(
            f"Invalid {provider} EDR payload"
        ) from exc

    raise ValueError(f"Unsupported EDR provider: {provider}")


def to_incident(alert: NormalizedEDRAlert) -> Incident:
    if not alert.username:
        raise ValueError("username is required to create an Incident")

    return Incident(
        alert_id=alert.alert_id,
        hostname=alert.hostname,
        username=alert.username,
        source_ip=alert.source_ip,
        process_name=alert.process_name,
        process_hash=alert.process_hash,
        severity=alert.severity,
        threat_type=alert.threat_type,
        indicators=alert.indicators,
    )
