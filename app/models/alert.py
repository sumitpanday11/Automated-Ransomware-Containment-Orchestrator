from datetime import datetime, timezone
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from app.models.incident import Severity


class Alert(BaseModel):
    alert_id: UUID = Field(default_factory=uuid4)
    alert_type: str
    description: str
    severity: Severity
    hostname: str
    username: str | None = None
    source_ip: str | None = None
    indicators: list[str] = Field(default_factory=list)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
