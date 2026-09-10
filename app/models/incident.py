from datetime import datetime, timezone
from enum import Enum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"


class HostInfo(BaseModel):
    hostname: str
    ip_address: str | None = None
    operating_system: str | None = None


class UserInfo(BaseModel):
    username: str
    domain: str | None = None


class ProcessInfo(BaseModel):
    process_name: str
    process_hash: str | None = None
    process_id: int | None = None
    command_line: str | None = None


class Incident(BaseModel):
    incident_id: UUID = Field(default_factory=uuid4)
    alert_id: UUID
    hostname: str
    username: str
    source_ip: str | None = None
    process_name: str | None = None
    process_hash: str | None = None
    severity: Severity
    threat_type: str
    indicators: list[str] = Field(default_factory=list)
    status: IncidentStatus = IncidentStatus.OPEN
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
