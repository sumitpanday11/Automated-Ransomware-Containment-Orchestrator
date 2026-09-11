from pydantic_settings import BaseSettings, SettingsConfigDict


class EDRSettings(BaseSettings):
    """Configuration for EDR provider integrations."""

    provider: str = "mock"
    api_url: str = ""
    api_key: str = ""

    model_config = SettingsConfigDict(
        env_prefix="EDR_",
        env_file=".env",
        extra="ignore",
    )