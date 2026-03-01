"""Application configuration via Pydantic Settings."""

from __future__ import annotations

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Server configuration loaded from environment variables."""

    model_config = {"env_prefix": "", "case_sensitive": True}

    # GCP
    GCP_PROJECT: str = "cybersorted-dev"
    FIRESTORE_DATABASE: str = "database-uk-dev"

    # Server
    ENVIRONMENT: str = "dev"
    PORT: int = 8080

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "prod"


settings = Settings()
