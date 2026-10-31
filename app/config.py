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
    # one public GET to the Bank of Canada for the USD/CAD rate behind cash estimates (app/fx.py); false turns it off
    fx_enabled: bool = True

    # where secrets live: the OS keychain (default) or systemd credentials on a headless server (see app/secrets.py)
    secrets_backend: Literal["keyring", "systemd"] = "keyring"
    credstore_dir: Path = Path("/etc/credstore.encrypted/personal-finance-mcp")

    # remote connector (python -m app.cli serve-http); none of these is secret
    public_url: str = ""  # e.g. https://vm.tailnet.ts.net ; the MCP endpoint is this plus /mcp
    http_port: int = 8765
    github_client_id: str = ""
    github_allowed_user_id: int = 0  # numeric GitHub user id, not the login name
    # refuse anonymous requests that arrive without X-Forwarded-For (a misconfigured Funnel target); set false only to
    # test the server directly on the VM
    require_forwarded_for: bool = True

    @field_validator("data_dir")
    @classmethod
    def _anchor_to_root(cls, v: Path) -> Path:
        # the server may be started from any directory, so a relative path must not depend on the working directory
        return v if v.is_absolute() else ROOT / v


settings = Settings()
