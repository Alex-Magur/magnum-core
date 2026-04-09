"""Forge Core API — Application Configuration.

Uses Pydantic Settings for environment-based configuration.
ADR Б15: Raw ENV secrets are prohibited — use JIT tokens via MCP Gateway.
"""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = {"env_prefix": "FORGE_"}

    env: str = "development"
    log_level: str = "INFO"
    api_host: str = "0.0.0.0"
    api_port: int = 8443

    # OAuth 2.1 (ADR Б2.1)
    oauth_issuer: str = ""
    oauth_jwks_uri: str = ""
    oauth_audience: str = "forge-core-api"

    # SQLite paths (ADR Б6)
    sqlite_control_plane_path: str = "/data/sqlite/control_plane.db"
    sqlite_agent_state_path: str = "/data/sqlite/agent_state_graph.db"
    sqlite_code_index_path: str = "/data/sqlite/code_index.db"


settings = Settings()
