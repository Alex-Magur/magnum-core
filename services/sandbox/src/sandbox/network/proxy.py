"""sandbox.network.proxy — Combined Egress Proxy.

ADR Блок 3.1: Composes the fast SSRF guard with OPA policy checks to
form a unified network proxy gateway.
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from sandbox.config import SandboxPolicy
from sandbox.network.ssrf_guard import SsrfGuard, SSRFViolation
from sandbox.opa.evaluator import OpaEvaluator

logger = logging.getLogger(__name__)


class EgressBlocked(RuntimeError):
    """Raised when an outbound request is completely blocked by policy."""


class EgressProxy:
    """Unified network gateway that orchestrates local SSRF checks and OPA policies."""

    def __init__(self, policy: SandboxPolicy) -> None:
        self.policy = policy
        self.ssrf_guard = SsrfGuard(policy)
        self.opa_evaluator = OpaEvaluator(policy)

    async def check_egress(self, method: str, url: str) -> None:
        """Validate an outbound HTTP request.

        Pipeline:
        1. Local SSRF check (IP literals, private CIDRs, DNS rebinding).
        2. OPA Policy evaluation (L7 methods, allowed hosts, custom rules).

        Raises:
            EgressBlocked: If any check fails.
        """
        method = method.upper()
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        # 1. SSRF & DNS Rebinding phase (Fast fail)
        try:
            await self.ssrf_guard.check_url_async(url)
        except SSRFViolation as exc:
            logger.warning(
                "Egress blocked by SSRF Guard | method=%s url=%s reason=%s",
                method, url, exc
            )
            # Structured audit block per ADR
            raise EgressBlocked(f"SSRF violation: {exc}") from exc

        # 2. OPA Evaluation phase
        input_doc = {
            "method": method,
            "host": hostname.lower(),
            "url": url,
        }

        decision = await self.opa_evaluator.evaluate(input_doc)
        
        if not decision.allowed:
            logger.warning(
                "Egress blocked by OPA Policy | method=%s url=%s decision_id=%s reason=%r",
                method, url, decision.policy_decision_id, decision.reason
            )
            # Raise the final unified exception type required by caller
            raise EgressBlocked(f"OPA policy violation: {decision.reason}")

        logger.debug(
            "Egress allowed | method=%s url=%s decision_id=%s",
            method, url, decision.policy_decision_id
        )
