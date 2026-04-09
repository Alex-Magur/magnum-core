"""sandbox.config — Settings and policy model for the OpenSandbox.

ADR Блок 3.1 (OpenShell Policy) and Блок 3.2 (JIT / Replay Protection).

Design decisions:
- ``SandboxSettings`` is a Pydantic ``BaseSettings`` so values can be
  overridden from environment variables (SANDBOX_* prefix) or a .env file
  without touching source.
- ``SandboxPolicy`` is an immutable dataclass derived from settings.  All
  runtime components (SsrfGuard, OpaEvaluator, EgressProxy, …) accept a
  ``SandboxPolicy`` so there is a single source of truth for policy data and
  tests can inject a custom policy without patching env vars.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Final

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# ---------------------------------------------------------------------------
# Constants — must mirror ADR 3.1 openshell-policy.yaml exactly
# ---------------------------------------------------------------------------

_ADR_DENY_PRIVATE_RANGES: Final[list[str]] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
]

# Loopback always blocked regardless of ADR explicit list
_IMPLICIT_DENY_RANGES: Final[list[str]] = [
    "127.0.0.0/8",
    "::1/128",
    "fc00::/7",   # ULA IPv6
]

_ADR_ALLOWED_METHODS: Final[list[str]] = ["GET", "POST", "PATCH"]
_ADR_ALLOWED_HOSTS: Final[list[str]] = ["api.github.com"]

_JIT_TOKEN_TTL_SECONDS: Final[int] = 60  # ADR 3.2


# ---------------------------------------------------------------------------
# Pydantic settings  (env prefix: SANDBOX_)
# ---------------------------------------------------------------------------

class SandboxSettings(BaseSettings):
    """Runtime-configurable settings for the OpenSandbox.

    All fields have sensible defaults matching ADR policy defaults.
    Override via environment variables:  ``SANDBOX_OPA_URL=http://…``
    """

    model_config = SettingsConfigDict(
        env_prefix="SANDBOX_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        # Extra fields in .env are silently ignored
        extra="ignore",
    )

    workspace_path: str = Field(
        default="/workspace",
        description="ADR 3.1: sole rw-mounted filesystem path for Landlock.",
    )
    opa_url: str = Field(
        default="http://localhost:8181",
        description="Base URL of the OPA REST API (without /v1/data suffix).",
    )
    opa_policy_path: str = Field(
        default="sandbox/egress",
        description="OPA policy path (used as POST /v1/data/<path>).",
    )

    # L7 allowlist — ADR 3.1
    allowed_methods: list[str] = Field(
        default_factory=lambda: list(_ADR_ALLOWED_METHODS),
        description="HTTP methods permitted by the L7 allowlist.",
    )
    allowed_hosts: list[str] = Field(
        default_factory=lambda: list(_ADR_ALLOWED_HOSTS),
        description="Hostnames permitted by the L7 allowlist.",
    )

    # SSRF protection — ADR 3.1
    deny_ip_literals: bool = Field(
        default=True,
        description="ADR 3.1: deny_ip_literals — block requests whose host is an IP address.",
    )
    deny_redirect_chains: bool = Field(
        default=True,
        description="ADR 3.1: deny_redirect_chains.",
    )
    deny_resolved_private_ips: bool = Field(
        default=True,
        description="ADR 3.1: deny_resolved_private_ips — DNS rebinding protection.",
    )
    deny_private_ranges: list[str] = Field(
        default_factory=lambda: list(_ADR_DENY_PRIVATE_RANGES),
        description="CIDR blocks to block for SSRF (ADR 3.1).",
    )

    # JIT / anti-replay — ADR 3.2
    jit_token_ttl_seconds: int = Field(
        default=_JIT_TOKEN_TTL_SECONDS,
        ge=1,
        description="TTL for JIT ephemeral tokens in seconds (ADR 3.2: 60 s).",
    )


# ---------------------------------------------------------------------------
# Immutable policy object consumed by all runtime components
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SandboxPolicy:
    """Immutable policy snapshot derived from ``SandboxSettings``.

    Components receive a ``SandboxPolicy`` at construction time so they never
    read settings after startup — no TOCTOU risk.
    """

    workspace_path: str
    opa_url: str
    opa_policy_path: str
    allowed_methods: tuple[str, ...]
    allowed_hosts: tuple[str, ...]
    deny_ip_literals: bool
    deny_redirect_chains: bool
    deny_resolved_private_ips: bool
    # Compiled network objects for O(1) membership checks
    deny_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    jit_token_ttl_seconds: int

    @classmethod
    def from_settings(cls, settings: SandboxSettings) -> "SandboxPolicy":
        """Build a policy from runtime settings, pre-compiling CIDR networks."""
        all_ranges = list(settings.deny_private_ranges) + list(_IMPLICIT_DENY_RANGES)
        compiled: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for cidr in all_ranges:
            try:
                compiled.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError as exc:
                raise ValueError(f"Invalid CIDR in policy: {cidr!r}") from exc

        return cls(
            workspace_path=settings.workspace_path,
            opa_url=settings.opa_url,
            opa_policy_path=settings.opa_policy_path,
            allowed_methods=tuple(m.upper() for m in settings.allowed_methods),
            allowed_hosts=tuple(h.lower() for h in settings.allowed_hosts),
            deny_ip_literals=settings.deny_ip_literals,
            deny_redirect_chains=settings.deny_redirect_chains,
            deny_resolved_private_ips=settings.deny_resolved_private_ips,
            deny_networks=tuple(compiled),
            jit_token_ttl_seconds=settings.jit_token_ttl_seconds,
        )

    def is_private_address(
        self, addr: str | ipaddress.IPv4Address | ipaddress.IPv6Address
    ) -> bool:
        """Return True if *addr* falls within any denied network."""
        if isinstance(addr, str):
            addr = ipaddress.ip_address(addr)
        return any(addr in net for net in self.deny_networks)


# ---------------------------------------------------------------------------
# Module-level default policy (singleton for production use)
# ---------------------------------------------------------------------------

def load_policy() -> SandboxPolicy:
    """Load and return the default policy from environment / .env."""
    return SandboxPolicy.from_settings(SandboxSettings())
