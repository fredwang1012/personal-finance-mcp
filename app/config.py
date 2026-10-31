"""Non-secret settings from the environment or the repo-root .env; a relative DATA_DIR is anchored to the repo root."""
from pathlib import Path
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[1]  # personal-finance-mcp/


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=ROOT / ".env", extra="ignore")

    plaid_env: Literal["sandbox", "production"] = "sandbox"
    data_dir: Path = ROOT / "data"
    country_codes: list[str] = ["CA"]

    @field_validator("data_dir")
    @classmethod
    def _anchor_to_root(cls, v: Path) -> Path:
        # the server may be started from any directory, so a relative path must not depend on the working directory
        return v if v.is_absolute() else ROOT / v


settings = Settings()
