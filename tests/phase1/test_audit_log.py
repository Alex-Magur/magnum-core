"""P1-AC8: Audit Log — Phase 1 Gate Test.

ADR References:
  - Б2.4 (Key Management & Cryptographic Operations Contract):
        "Any key operation (rotation, revocation, issuance) MUST generate a
         mandatory record: [key_id, action, operator, reason, timestamp]."
  - Б0.2 (Constrained Decoding policy):
        "Decode failures must be audited."
  - Б16 P1-AC8 (Audit Log):
        "All key management events are recorded in the audit log with the
         mandatory fields: key_id, action, operator, reason, ts."

Acceptance criteria verified by this file
------------------------------------------
P1-AC8-a  write_key_event emits a WARNING record on the "forge.audit" logger
          with schema="forge.audit.key_event.v1" and all mandatory fields:
          key_id, action, operator, reason, ts.
P1-AC8-b  write_key_event accepts exactly the three permitted actions:
          "rotate", "revoke", "issue". Any other value raises ValueError.
P1-AC8-c  write_manifest_event emits a WARNING record on "forge.audit" with
          schema="forge.audit.manifest_event.v1" and all mandatory fields:
          tool_name, server_id, manifest_hash, action, reason, ts.
P1-AC8-d  write_manifest_event accepts exactly the three permitted actions:
          "quarantine", "verify_ok", "constrained_decode_fail". Any other
          value raises ValueError.
P1-AC8-e  The ts field defaults to the current UTC epoch when not provided
          (numeric, close to time.time()); it can be overridden by the caller.
P1-AC8-f  Records are emitted at logging.WARNING level — not DEBUG or INFO.
P1-AC8-g  The JSON payload is compact (no extraneous whitespace), valid JSON,
          and contains exactly the expected top-level keys (no extras, no missing).
P1-AC8-h  The two schemas are mutually exclusive: a key_event record never
          contains tool_name; a manifest_event record never contains key_id.

Test strategy
-------------
All tests use caplog to capture records from the "forge.audit" logger.
The caplog fixture is function-scoped by default — each test sees only its
own records, ensuring isolation.
"""

from __future__ import annotations

import json
import logging
import time

import pytest

from forge_security.audit.logger import write_key_event, write_manifest_event

pytestmark = pytest.mark.phase1

# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #

_AUDIT_PREFIX = "AUDIT "

def _parse_audit(caplog: pytest.LogCaptureFixture) -> list[dict]:
    """Extract and JSON-parse all forge.audit records from caplog."""
    records = [r for r in caplog.records if r.name == "forge.audit"]
    return [
        json.loads(r.getMessage()[len(_AUDIT_PREFIX):])
        for r in records
        if r.getMessage().startswith(_AUDIT_PREFIX)
    ]


def _single_audit(caplog: pytest.LogCaptureFixture) -> dict:
    """Assert exactly one forge.audit record exists; return its parsed payload."""
    payloads = _parse_audit(caplog)
    assert len(payloads) == 1, (
        f"Expected exactly 1 audit record, got {len(payloads)}: {payloads}"
    )
    return payloads[0]


# --------------------------------------------------------------------------- #
# P1-AC8-a/b: write_key_event                                                 #
# --------------------------------------------------------------------------- #

class TestWriteKeyEvent:
    """write_key_event contract: schema, fields, actions, ts, level."""

    def test_rotate_action_produces_correct_schema(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """P1-AC8-a: rotate produces forge.audit.key_event.v1 with all fields."""
        with caplog.at_level(logging.WARNING, logger="forge.audit"):
            write_key_event(
                key_id="gateway-signing-2026-04",
                action="rotate",
                operator="svid_watcher",
                reason="scheduled_ttl",
            )

        payload = _single_audit(caplog)

        assert payload["schema"] == "forge.audit.key_event.v1"
        assert payload["key_id"] == "gateway-signing-2026-04"
        assert payload["action"] == "rotate"
        assert payload["operator"] == "svid_watcher"
        assert payload["reason"] == "scheduled_ttl"
        assert "ts" in payload and isinstance(payload["ts"], (int, float))

    def test_revoke_action_accepted(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """P1-AC8-b: "revoke" is a permitted key action."""
        with caplog.at_level(logging.WARNING, logger="forge.audit"):
            write_key_event(
                key_id="old-key-2024",
                action="revoke",
                operator="security_ops",
                reason="compromise_suspected",
            )

        payload = _single_audit(caplog)
        assert payload["action"] == "revoke"
        assert payload["schema"] == "forge.audit.key_event.v1"

    def test_issue_action_accepted(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """P1-AC8-b: "issue" is a permitted key action."""
        with caplog.at_level(logging.WARNING, logger="forge.audit"):
            write_key_event(
                key_id="new-key-2026-05",
                action="issue",
                operator="key_ceremony",
                reason="initial_provisioning",
            )

        payload = _single_audit(caplog)
        assert payload["action"] == "issue"

    @pytest.mark.parametrize("bad_action", [
        "delete", "create", "UPDATE", "ROTATE", "", "rotate;drop table",
    ])
    def test_invalid_action_raises_value_error(self, bad_action: str) -> None:
        """P1-AC8-b: Invalid key action raises ValueError — fail fast."""
        with pytest.raises(ValueError, match="Invalid key action"):
            write_key_event(
                key_id="some-key",
                action=bad_action,  # type: ignore[arg-type]
                operator="test",
                reason="test",
            )

    def test_ts_defaults_to_current_time(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """P1-AC8-e: ts defaults to time.time() when not supplied (within 5s tolerance)."""
        before = time.time()
        with caplog.at_level(logging.WARNING, logger="forge.audit"):
            write_key_event(
                key_id="k", action="rotate", operator="op", reason="r"
            )
        after = time.time()

        payload = _single_audit(caplog)
        ts = payload["ts"]
        assert isinstance(ts, (int, float)), f"ts is not numeric: {ts!r}"
        assert before <= ts <= after, (
            f"ts={ts} not in expected range [{before}, {after}]"
        )

    def test_ts_can_be_overridden(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """P1-AC8-e: Caller-supplied ts is preserved exactly in the record."""
        fixed_ts = 1_700_000_000.0
        with caplog.at_level(logging.WARNING, logger="forge.audit"):
            write_key_event(
                key_id="k", action="rotate", operator="op", reason="r",
                ts=fixed_ts,
            )

        payload = _single_audit(caplog)
        assert payload["ts"] == fixed_ts

    def test_record_emitted_at_warning_level(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """P1-AC8-f: Audit records are WARNING — not DEBUG or INFO."""
        with caplog.at_level(logging.DEBUG, logger="forge.audit"):
            write_key_event(key_id="k", action="issue", operator="op", reason="r")

        records = [r for r in caplog.records if r.name == "forge.audit"]
        assert all(r.levelno == logging.WARNING for r in records), (
            f"Expected WARNING level; got: {[r.levelno for r in records]}"
        )

    def test_logger_name_is_forge_audit(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """P1-AC8-f: Records originate from the 'forge.audit' logger."""
        with caplog.at_level(logging.WARNING, logger="forge.audit"):
            write_key_event(key_id="k", action="rotate", operator="op", reason="r")

        matching = [r for r in caplog.records if r.name == "forge.audit"]
        assert len(matching) == 1

    def test_key_event_exact_field_set(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """P1-AC8-g/h: key_event record has exactly the specified top-level keys."""
        with caplog.at_level(logging.WARNING, logger="forge.audit"):
            write_key_event(
                key_id="k", action="rotate", operator="op", reason="r"
            )

        payload = _single_audit(caplog)
        expected_keys = {"schema", "key_id", "action", "operator", "reason", "ts"}
        assert set(payload.keys()) == expected_keys, (
            f"Unexpected keys in key_event record: "
            f"extra={set(payload.keys()) - expected_keys}, "
            f"missing={expected_keys - set(payload.keys())}"
        )
        # P1-AC8-h: key_event must NOT contain manifest fields
        assert "tool_name" not in payload
        assert "server_id" not in payload
        assert "manifest_hash" not in payload

    def test_record_is_compact_valid_json(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """P1-AC8-g: The AUDIT payload is compact JSON (no extraneous spaces)."""
        with caplog.at_level(logging.WARNING, logger="forge.audit"):
            write_key_event(key_id="k", action="issue", operator="op", reason="r")

        raw_records = [r for r in caplog.records if r.name == "forge.audit"]
        assert len(raw_records) == 1
        raw_msg = raw_records[0].getMessage()
        assert raw_msg.startswith(_AUDIT_PREFIX)

        json_str = raw_msg[len(_AUDIT_PREFIX):]

        # Must be valid JSON
        parsed = json.loads(json_str)
        assert isinstance(parsed, dict)

        # Compact: re-serialising with same separators should yield identical string
        compact = json.dumps(parsed, separators=(",", ":"))
        assert json_str == compact, (
            f"Audit record is not compact JSON. "
            f"Got:      {json_str!r}\n"
            f"Expected: {compact!r}"
        )


# --------------------------------------------------------------------------- #
# P1-AC8-c/d: write_manifest_event                                            #
# --------------------------------------------------------------------------- #

class TestWriteManifestEvent:
    """write_manifest_event contract: schema, fields, actions, compactness."""

    def test_quarantine_action_produces_correct_schema(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """P1-AC8-c: quarantine produces forge.audit.manifest_event.v1."""
        with caplog.at_level(logging.WARNING, logger="forge.audit"):
            write_manifest_event(
                tool_name="search_code",
                server_id="spiffe://forge.local/mcp-gateway",
                manifest_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4",
                action="quarantine",
                reason="invalid_signature",
            )

        payload = _single_audit(caplog)

        assert payload["schema"] == "forge.audit.manifest_event.v1"
        assert payload["tool_name"] == "search_code"
        assert payload["server_id"] == "spiffe://forge.local/mcp-gateway"
        assert payload["manifest_hash"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4"
        assert payload["action"] == "quarantine"
        assert payload["reason"] == "invalid_signature"
        assert "ts" in payload and isinstance(payload["ts"], (int, float))

    def test_verify_ok_action_accepted(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """P1-AC8-d: "verify_ok" is a permitted manifest action."""
        with caplog.at_level(logging.WARNING, logger="forge.audit"):
            write_manifest_event(
                tool_name="code_edit",
                server_id="spiffe://forge.local/mcp-server",
                manifest_hash="abc123",
                action="verify_ok",
                reason="signature_valid",
            )

        payload = _single_audit(caplog)
        assert payload["action"] == "verify_ok"

    def test_constrained_decode_fail_action_accepted(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """P1-AC8-d: "constrained_decode_fail" is a permitted manifest action (ADR Б0.2)."""
        with caplog.at_level(logging.WARNING, logger="forge.audit"):
            write_manifest_event(
                tool_name="search_code",
                server_id="spiffe://forge.local/mcp-gateway",
                manifest_hash="deadbeef",
                action="constrained_decode_fail",
                reason="schema_violations_after_3_attempts",
            )

        payload = _single_audit(caplog)
        assert payload["action"] == "constrained_decode_fail"
        assert payload["schema"] == "forge.audit.manifest_event.v1"

    @pytest.mark.parametrize("bad_action", [
        "block", "verify_fail", "ok", "QUARANTINE", "", "quarantine;1=1",
    ])
    def test_invalid_manifest_action_raises_value_error(
        self, bad_action: str
    ) -> None:
        """P1-AC8-d: Invalid manifest action raises ValueError — fail fast."""
        with pytest.raises(ValueError, match="Invalid manifest action"):
            write_manifest_event(
                tool_name="x",
                server_id="spiffe://forge.local/x",
                manifest_hash="hash",
                action=bad_action,  # type: ignore[arg-type]
                reason="test",
            )

    def test_manifest_event_exact_field_set(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """P1-AC8-g/h: manifest_event has exactly the specified top-level keys."""
        with caplog.at_level(logging.WARNING, logger="forge.audit"):
            write_manifest_event(
                tool_name="t",
                server_id="s",
                manifest_hash="h",
                action="verify_ok",
                reason="r",
            )

        payload = _single_audit(caplog)
        expected_keys = {
            "schema", "tool_name", "server_id", "manifest_hash",
            "action", "reason", "ts",
        }
        assert set(payload.keys()) == expected_keys, (
            f"Unexpected keys: extra={set(payload.keys()) - expected_keys}, "
            f"missing={expected_keys - set(payload.keys())}"
        )
        # P1-AC8-h: manifest_event must NOT contain key fields
        assert "key_id" not in payload
        assert "operator" not in payload

    def test_ts_override_preserved(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """P1-AC8-e: Caller-supplied ts is written exactly."""
        pinned_ts = 1_600_000_000.123
        with caplog.at_level(logging.WARNING, logger="forge.audit"):
            write_manifest_event(
                tool_name="t", server_id="s", manifest_hash="h",
                action="quarantine", reason="r",
                ts=pinned_ts,
            )

        payload = _single_audit(caplog)
        assert payload["ts"] == pinned_ts

    def test_manifest_record_is_compact_valid_json(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """P1-AC8-g: manifest_event payload is compact JSON (no spurious spaces)."""
        with caplog.at_level(logging.WARNING, logger="forge.audit"):
            write_manifest_event(
                tool_name="t", server_id="s", manifest_hash="h",
                action="verify_ok", reason="r",
            )

        raw_records = [r for r in caplog.records if r.name == "forge.audit"]
        assert len(raw_records) == 1
        json_str = raw_records[0].getMessage()[len(_AUDIT_PREFIX):]

        parsed = json.loads(json_str)
        compact = json.dumps(parsed, separators=(",", ":"))
        assert json_str == compact


# --------------------------------------------------------------------------- #
# P1-AC8-h: Schema mutual exclusivity                                         #
# --------------------------------------------------------------------------- #

class TestSchemaMutualExclusivity:
    """key_event and manifest_event schemas are structurally disjoint."""

    def test_both_schemas_have_different_names(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """P1-AC8-h: key_event.v1 and manifest_event.v1 are distinct schema identifiers."""
        with caplog.at_level(logging.WARNING, logger="forge.audit"):
            write_key_event(key_id="k", action="rotate", operator="op", reason="r")
            write_manifest_event(
                tool_name="t", server_id="s", manifest_hash="h",
                action="quarantine", reason="r",
            )

        payloads = _parse_audit(caplog)
        assert len(payloads) == 2

        schemas = {p["schema"] for p in payloads}
        assert schemas == {
            "forge.audit.key_event.v1",
            "forge.audit.manifest_event.v1",
        }

    def test_key_event_never_contains_manifest_fields(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """key_event records have no tool_name, server_id, or manifest_hash."""
        with caplog.at_level(logging.WARNING, logger="forge.audit"):
            for action in ("rotate", "revoke", "issue"):
                write_key_event(key_id="k", action=action, operator="op", reason="r")  # type: ignore[arg-type]

        for payload in _parse_audit(caplog):
            assert "tool_name" not in payload
            assert "server_id" not in payload
            assert "manifest_hash" not in payload

    def test_manifest_event_never_contains_key_fields(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """manifest_event records have no key_id or operator."""
        with caplog.at_level(logging.WARNING, logger="forge.audit"):
            for action in ("quarantine", "verify_ok", "constrained_decode_fail"):
                write_manifest_event(
                    tool_name="t", server_id="s", manifest_hash="h",
                    action=action, reason="r",  # type: ignore[arg-type]
                )

        for payload in _parse_audit(caplog):
            assert "key_id" not in payload
            assert "operator" not in payload

    def test_multiple_events_are_independent_lines(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Each write_* call produces exactly one audit line — no aggregation."""
        with caplog.at_level(logging.WARNING, logger="forge.audit"):
            write_key_event(key_id="k1", action="rotate", operator="op", reason="r")
            write_key_event(key_id="k2", action="revoke", operator="op", reason="r")
            write_manifest_event(
                tool_name="t", server_id="s", manifest_hash="h",
                action="quarantine", reason="r",
            )

        payloads = _parse_audit(caplog)
        assert len(payloads) == 3

        key_ids = [p.get("key_id") for p in payloads if "key_id" in p]
        assert "k1" in key_ids
        assert "k2" in key_ids
