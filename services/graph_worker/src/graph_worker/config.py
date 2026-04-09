"""Graph Worker — Configuration."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Graph Worker settings."""

    model_config = {"env_prefix": "FORGE_GRAPH_"}

    env: str = "development"
    log_level: str = "INFO"
    sqlite_state_path: str = "/data/sqlite/agent_state_graph.db"
    mcp_gateway_url: str = "https://mcp-gateway:8443"
    reconciliation_timeout_minutes: int = 10  # ADR Б4.1
