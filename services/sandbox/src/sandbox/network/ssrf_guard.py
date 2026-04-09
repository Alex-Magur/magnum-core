"""sandbox.network.ssrf_guard — SSRF + DNS-Rebinding Protection.

ADR Блок 3.1: Strict L7 inspection, SSRF protection with DNS rebinding guards.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from urllib.parse import urlparse

from sandbox.config import SandboxPolicy

logger = logging.getLogger(__name__)


class SSRFViolation(ValueError):
    """Raised when an SSRF check fails."""


class SsrfGuard:
    """Validates URLs against the strict SSRF constraints defined in the ADR."""

    def __init__(self, policy: SandboxPolicy) -> None:
        self.policy = policy

    def check_url(self, url: str) -> None:
        """Validate a URL synchronously.

        Performs:
        1. Scheme validation (http/https).
        2. IP literal detection and policy check.
        3. DNS resolution to prevent rebinding to private IPs.

        Raises:
            SSRFViolation: If the URL violates any security constraint.
        """
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise SSRFViolation(f"Unsupported scheme: {parsed.scheme!r}")

        hostname = parsed.hostname
        if not hostname:
            raise SSRFViolation("Missing hostname in URL")

        is_ip_literal = False
        try:
            # Check if it's a valid IP string
            ip_obj = ipaddress.ip_address(hostname)
            is_ip_literal = True

            if self.policy.deny_ip_literals:
                raise SSRFViolation(f"IP literals are denied by policy: {hostname!r}")

            if self.policy.is_private_address(ip_obj):
                raise SSRFViolation(f"Access to private IP range denied: {hostname!r}")
        except ValueError as exc:
            if isinstance(exc, SSRFViolation):
                raise

        # DNS Resolution (DNS-rebinding protection)
        if self.policy.deny_resolved_private_ips and not is_ip_literal:
            try:
                # getaddrinfo returns resolved IPs for the hostname
                addrs = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
                for addr_info in addrs:
                    # addr_info[4] is the sockaddr tuple, [0] is the IP string
                    ip_str = addr_info[4][0]
                    resolved_ip = ipaddress.ip_address(ip_str)
                    if self.policy.is_private_address(resolved_ip):
                        raise SSRFViolation(
                            f"Hostname {hostname!r} resolved to a private IP: {ip_str} (DNS rebinding blocked)"
                        )
            except socket.gaierror as exc:
                raise SSRFViolation(f"DNS resolution failed for {hostname!r}: {exc}") from exc

        logger.debug("SSRF guard passed for URL: %s", url)

    async def check_url_async(self, url: str) -> None:
        """Async wrapper for the URL check (typically CPU/network-bound but fast)."""
        import asyncio
        loop = asyncio.get_running_loop()
        # Run DNS resolution safely in a threadpool to avoid blocking event loop
        await loop.run_in_executor(None, self.check_url, url)
