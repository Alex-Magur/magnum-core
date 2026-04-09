"""sandbox.opa.evaluator — OPA Integration.

ADR Блок 3.1: OPA egress policy evaluation.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from typing import Any

import httpx

from sandbox.config import SandboxPolicy

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class OpaDecision:
    allowed: bool
    reason: str
    policy_decision_id: str


class OpaEvaluator:
    """Evaluates requests against an external Open Policy Agent (OPA) server.
    
    Includes a pure-Python fallback for CI and fail-secure operations.
    """

    def __init__(self, policy: SandboxPolicy) -> None:
        self.policy = policy
        self.opa_base = policy.opa_url.rstrip("/")
        self.policy_path = policy.opa_policy_path.strip("/")
        self.eval_url = f"{self.opa_base}/v1/data/{self.policy_path}"

    async def evaluate(self, input_doc: dict[str, Any]) -> OpaDecision:
        """Evaluate the input doc against OPA, falling back to local Python eval if offline."""
        decision_id = str(uuid.uuid4())

        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.post(self.eval_url, json={"input": input_doc})
                resp.raise_for_status()
                data = resp.json()

            # Follow standard OPA layout where `result` holds the policy output
            result = data.get("result")
            if isinstance(result, dict):
                allowed = result.get("allow", False)
            else:
                allowed = bool(result)

            reason = "OPA policy evaluation complete" if allowed else "OPA policy denied request"
            return OpaDecision(allowed=allowed, reason=reason, policy_decision_id=decision_id)

        except (httpx.RequestError, httpx.HTTPStatusError) as exc:
            logger.warning("OPA evaluation failed (%s). Using fail-secure pure-Python fallback.", exc)
            return self._fallback_evaluate(input_doc, decision_id)
        except Exception as exc:
            logger.error("Unexpected error in OPA evaluation: %s", exc)
            return OpaDecision(False, f"Internal error: {exc}", decision_id)

    def _fallback_evaluate(self, input_doc: dict[str, Any], decision_id: str) -> OpaDecision:
        """Pure-Python fallback embodying ADR 3.1 restrictions directly."""
        method = input_doc.get("method", "").upper()
        host = input_doc.get("host", "").lower()
        resolved_ip = input_doc.get("resolved_ip")

        if method and method not in self.policy.allowed_methods:
            return OpaDecision(False, f"Method {method!r} not in L7 allowlist", decision_id)

        if host and host not in self.policy.allowed_hosts:
            return OpaDecision(False, f"Host {host!r} not in L7 allowlist", decision_id)

        # In fallback mode, the ssrf_guard is expected to handle IP-level checks, 
        # but we double check if the resolved IP passed in the doc is private as a defense layer.
        if resolved_ip:
            try:
                import ipaddress
                ip_obj = ipaddress.ip_address(resolved_ip)
                if self.policy.is_private_address(ip_obj):
                    return OpaDecision(False, f"Resolved IP {resolved_ip} is in denied private range", decision_id)
            except ValueError:
                pass

        return OpaDecision(True, "Fallback local policy allowed request", decision_id)
