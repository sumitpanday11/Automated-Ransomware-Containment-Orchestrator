from app.identity.adapter import IdentityProviderAdapter
from app.identity.mock import MockIdentityProvider


def create_identity_provider(provider: str) -> IdentityProviderAdapter:
    """Create the configured identity provider."""

    if provider.lower() == "mock":
        return MockIdentityProvider()

    raise ValueError(f"Unsupported identity provider: {provider}")
