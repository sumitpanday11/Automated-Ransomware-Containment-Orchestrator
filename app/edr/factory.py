from app.edr.adapter import EDRAdapter
from app.edr.mock import MockEDRProvider


def create_edr_provider(provider: str = "mock") -> EDRAdapter:
    """Create an EDR provider based on configuration."""

    if provider.lower() == "mock":
        return MockEDRProvider()

    raise ValueError(f"Unsupported EDR provider: {provider}")