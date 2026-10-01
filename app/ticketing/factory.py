import os

from .adapter import TicketingAdapter
from .mock import MockTicketingAdapter


def get_ticketing_adapter() -> TicketingAdapter:
    provider = os.getenv("TICKETING_PROVIDER", "mock").lower()

    if provider == "mock":
        return MockTicketingAdapter()

    raise ValueError(f"Unsupported ticketing provider: {provider}")