import os

from .adapter import NotificationAdapter
from .mock import MockNotificationAdapter


def get_notification_adapter() -> NotificationAdapter:
    provider = os.getenv("NOTIFICATION_PROVIDER", "mock").lower()

    if provider == "mock":
        return MockNotificationAdapter()

    raise ValueError(f"Unsupported notification provider: {provider}")