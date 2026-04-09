"""Internal audit writer for the auth module.

ADR Б2.1 / Б2.4: Every token rejection and key event must generate
a mandatory record in audit_log.

Scope: STRICTLY limited to forge_api/auth — does NOT touch the
forge_security.audit lib (placeholder, Phase 1 isolation constraint).

The audit record format is:
    [event, reason, ts, actor, detail]

In the current phase this writes structured JSON to stderr/logger at
WARNING level so it is captured by any log aggregator (OTel, journald).
A future phase will route this to the persistent audit_log SQLite table
via forge_security.audit when that block is implemented.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

_audit_logger = logging.getLogger("forge_api.audit")


async def write_auth_audit_event(
    event: str,
    reason: str,
    *,
    actor: str = "system",
    token_snippet: str = "",
    **extra: Any,
) -> None:
    """Write a structured audit event for an auth decision.

    Args:
        event:         Short event name, e.g. ``jwt_rejected``, ``token_binding_fail``.
        reason:        Machine-readable reason code or description.
        actor:         Identity performing the action (sub claim, or "system").
        token_snippet: First ~16 chars of the raw token for correlation (never full token).
        **extra:       Any additional key-value context to include.
    """
    record: dict[str, Any] = {
        "event": event,
        "reason": reason,
        "ts": time.time(),
        "actor": actor,
        "token_snippet": token_snippet,
        **extra,
    }
    _audit_logger.warning("AUDIT %s", json.dumps(record, default=str))
