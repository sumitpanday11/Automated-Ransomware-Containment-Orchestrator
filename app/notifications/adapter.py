from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass
class SOCNotification:
    incident_id: str
    host: str
    user: str
    threat: str
    severity: str
    status: str
    evidence_location: Optional[str] = None


@dataclass
class NotificationResult:
    success: bool
    notification_id: Optional[str] = None
    provider: Optional[str] = None
    message: Optional[str] = None


class NotificationAdapter(ABC):

    @abstractmethod
    def send_notification(
        self,
        notification: SOCNotification,
    ) -> NotificationResult:
        raise NotImplementedError