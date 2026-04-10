"""P1-AC5: Constrained Decoding — Phase 1 Gate Test.

ADR References:
  - Б0.2 (Constrained Decoding & Zero-Trust):
        "Tool call generation is guaranteed by Constrained Decoding.
         Syntactic errors handled by deterministic policy:
         reject → retry (constrained) → fail + alert."
  - Б16 P1-AC5 (Constrained Decoding Logic):
        "When the agent forms a tool call, the Gateway accepts ONLY a valid
         JSON Schema. On invalidity: reject → retry (constrained) → fail
         (after K=2)."

Acceptance criteria verified by this file
------------------------------------------
P1-AC5-a  ConstrainedDecoder construction validates the schema itself;
          an invalid JSON Schema raises jsonschema.SchemaError immediately.

P1-AC5-b  Full deterministic state machine transitions:
            IDLE + valid   → ACCEPTED  (terminal, returns ValidationResult)
            IDLE + invalid → RETRY     (returns ValidationResult, status=RETRY)
            RETRY + invalid, failures ≤ max_retries → RETRY
            RETRY + invalid, failures > max_retries → FAILED (raises)
            RETRY + valid  → ACCEPTED  (recovery path)

P1-AC5-c  ValidationResult fields are accurate for every state transition:
          status, tool_call, errors, attempt (1-indexed), failures,
          retries_remaining.

P1-AC5-d  ConstrainedDecodingError carries tool_name, errors, total_failures.
          DecoderTerminatedError is raised when validate() is called on an
          already-terminal decoder (ACCEPTED or FAILED).

P1-AC5-e  On FAILED state: the "forge.audit" logger emits a WARNING record
          with schema="forge.audit.manifest_event.v1",
          action="constrained_decode_fail", and all mandatory fields.

P1-AC5-f  reset() restores the decoder to IDLE, allowing reuse across
          multiple tool-call sequences without rebuilding Draft7Validator.

P1-AC5-g  Edge cases: max_retries=0 (one-shot), negative max_retries
          (ValueError), max_attempts property, repr().

Test strategy
-------------
All tests use a simple in-memory JSON Schema — no LLM, no network, no
external processes. The state machine is deterministic and testable via the
public API alone.
"""

from __future__ import annotations

import json
import logging

import jsonschema
import pytest

from mcp_gateway.constrained_decoding.validator import (
    ConstrainedDecoder,
    ConstrainedDecodingError,
    DecoderState,
    DecoderTerminatedError,
    ValidationStatus,
)

pytestmark = pytest.mark.phase1


# --------------------------------------------------------------------------- #
# Shared test data                                                             #
# --------------------------------------------------------------------------- #

# JSON Schema used across all tests.
# Represents a minimal MCP tool call: {tool_name: str, args: object}
TOOL_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "tool_name": {"type": "string"},
        "args":      {"type": "object"},
    },
    "required": ["tool_name", "args"],
    "additionalProperties": False,
}

# Valid tool call — satisfies TOOL_SCHEMA
VALID_CALL: dict = {"tool_name": "search_code", "args": {"query": "def authenticate"}}

# Invalid: missing required "args" field
INVALID_MISSING_ARGS: dict = {"tool_name": "search_code"}

# Invalid: wrong type for "tool_name"
INVALID_WRONG_TYPE: dict = {"tool_name": 42, "args": {}}

# Invalid: extra property rejected by additionalProperties=false
INVALID_EXTRA_PROP: dict = {"tool_name": "search_code", "args": {}, "inject": True}


# --------------------------------------------------------------------------- #
# P1-AC5-a: Construction & schema self-validation                             #
# --------------------------------------------------------------------------- #

class TestConstruction:
    """Schema and argument validation at construction time."""

    def test_valid_schema_constructs_without_error(self) -> None:
        """ConstrainedDecoder accepts a well-formed JSON Schema."""
        decoder = ConstrainedDecoder(TOOL_SCHEMA)
        assert decoder.state == DecoderState.IDLE
        assert decoder.failures == 0
        assert decoder.max_retries == 2
        assert decoder.max_attempts == 3  # K + 1

    def test_invalid_schema_raises_schema_error_at_construction(self) -> None:
        """The schema itself is validated at construction — fail fast."""
        bad_schema = {"type": {"this": "is-not-a-valid-type-value"}}
        with pytest.raises(jsonschema.SchemaError):
            ConstrainedDecoder(bad_schema)

    def test_negative_max_retries_raises_value_error(self) -> None:
        """max_retries=-1 is semantically nonsensical — fail fast."""
        with pytest.raises(ValueError, match="max_retries must be >= 0"):
            ConstrainedDecoder(TOOL_SCHEMA, max_retries=-1)

    def test_max_retries_zero_is_allowed(self) -> None:
        """max_retries=0 means zero retries — one-shot decoder."""
        decoder = ConstrainedDecoder(TOOL_SCHEMA, max_retries=0)
        assert decoder.max_retries == 0
        assert decoder.max_attempts == 1
        assert decoder.retries_remaining == 0

    def test_constructor_metadata_stored(self) -> None:
        """tool_name, server_id, manifest_hash are stored for audit events."""
        decoder = ConstrainedDecoder(
            TOOL_SCHEMA,
            tool_name="search_code",
            server_id="spiffe://forge.local/mcp-gateway",
            manifest_hash="deadbeef",
        )
        assert decoder.tool_name == "search_code"


# --------------------------------------------------------------------------- #
# P1-AC5-b: Deterministic state machine transitions                           #
# --------------------------------------------------------------------------- #

class TestStateMachine:
    """Exhaustive state machine transition coverage (ADR P1-AC5)."""

    def test_idle_plus_valid_transitions_to_accepted(self) -> None:
        """IDLE + valid tool call → ACCEPTED (terminal)."""
        decoder = ConstrainedDecoder(TOOL_SCHEMA)
        assert decoder.state == DecoderState.IDLE

        result = decoder.validate(VALID_CALL)

        assert decoder.state == DecoderState.ACCEPTED
        assert result.status == ValidationStatus.ACCEPTED

    def test_idle_plus_invalid_transitions_to_retry(self) -> None:
        """IDLE + invalid tool call → RETRY (retries remaining)."""
        decoder = ConstrainedDecoder(TOOL_SCHEMA, max_retries=2)
        assert decoder.state == DecoderState.IDLE

        result = decoder.validate(INVALID_MISSING_ARGS)

        assert decoder.state == DecoderState.RETRY
        assert result.status == ValidationStatus.RETRY

    def test_full_retry_sequence_ends_in_failed(self) -> None:
        """IDLE → RETRY → RETRY → FAILED: K=2 retries exhausted raises ConstrainedDecodingError.

        This is the primary ADR P1-AC5 contract:
          attempt 1 → RETRY (1 failure, 1 retry remaining)
          attempt 2 → RETRY (2 failures, 0 retries remaining)
          attempt 3 → FAILED → ConstrainedDecodingError raised
        """
        decoder = ConstrainedDecoder(TOOL_SCHEMA, max_retries=2)

        # Attempt 1 → RETRY
        r1 = decoder.validate(INVALID_MISSING_ARGS)
        assert r1.status == ValidationStatus.RETRY
        assert decoder.state == DecoderState.RETRY
        assert decoder.failures == 1
        assert decoder.retries_remaining == 1

        # Attempt 2 → RETRY (last retry available)
        r2 = decoder.validate(INVALID_MISSING_ARGS)
        assert r2.status == ValidationStatus.RETRY
        assert decoder.state == DecoderState.RETRY
        assert decoder.failures == 2
        assert decoder.retries_remaining == 0

        # Attempt 3 → FAILED → must raise
        with pytest.raises(ConstrainedDecodingError):
            decoder.validate(INVALID_MISSING_ARGS)

        assert decoder.state == DecoderState.FAILED

    def test_retry_then_recovery_transitions_to_accepted(self) -> None:
        """IDLE → RETRY → ACCEPTED: valid call after one failure recovers cleanly."""
        decoder = ConstrainedDecoder(TOOL_SCHEMA, max_retries=2)

        result_fail = decoder.validate(INVALID_MISSING_ARGS)
        assert result_fail.status == ValidationStatus.RETRY
        assert decoder.failures == 1

        # Recovery: valid call on second attempt
        result_ok = decoder.validate(VALID_CALL)
        assert result_ok.status == ValidationStatus.ACCEPTED
        assert decoder.state == DecoderState.ACCEPTED
        # Failure count preserved in the result (1 failure occurred)
        assert result_ok.failures == 1

    def test_max_retries_zero_fails_on_first_invalid(self) -> None:
        """max_retries=0: first invalid attempt immediately raises ConstrainedDecodingError."""
        decoder = ConstrainedDecoder(TOOL_SCHEMA, max_retries=0)

        with pytest.raises(ConstrainedDecodingError) as exc_info:
            decoder.validate(INVALID_MISSING_ARGS)

        assert decoder.state == DecoderState.FAILED
        assert exc_info.value.total_failures == 1

    def test_max_retries_zero_accepts_valid_on_first_attempt(self) -> None:
        """max_retries=0 still accepts a valid call (no retries needed)."""
        decoder = ConstrainedDecoder(TOOL_SCHEMA, max_retries=0)
        result = decoder.validate(VALID_CALL)
        assert result.status == ValidationStatus.ACCEPTED


# --------------------------------------------------------------------------- #
# P1-AC5-c: ValidationResult field accuracy                                   #
# --------------------------------------------------------------------------- #

class TestValidationResultFields:
    """Every field of ValidationResult is accurate for each state."""

    def test_accepted_result_fields(self) -> None:
        """ACCEPTED result: errors=[], tool_call=original dict, attempt=1."""
        decoder = ConstrainedDecoder(TOOL_SCHEMA)
        result = decoder.validate(VALID_CALL)

        assert result.status == ValidationStatus.ACCEPTED
        assert result.tool_call == VALID_CALL
        assert result.errors == []
        assert result.attempt == 1
        assert result.failures == 0
        assert result.retries_remaining == 2  # max_retries untouched

    def test_retry_result_fields_first_failure(self) -> None:
        """RETRY result (failure 1): attempt=1, failures=1, retries_remaining=1."""
        decoder = ConstrainedDecoder(TOOL_SCHEMA, max_retries=2)
        result = decoder.validate(INVALID_MISSING_ARGS)

        assert result.status == ValidationStatus.RETRY
        assert result.tool_call == INVALID_MISSING_ARGS
        assert len(result.errors) >= 1               # at least one violation
        assert isinstance(result.errors[0], str)     # human-readable messages
        assert result.attempt == 1
        assert result.failures == 1
        assert result.retries_remaining == 1

    def test_retry_result_fields_second_failure(self) -> None:
        """RETRY result (failure 2): attempt=2, failures=2, retries_remaining=0."""
        decoder = ConstrainedDecoder(TOOL_SCHEMA, max_retries=2)
        decoder.validate(INVALID_MISSING_ARGS)       # failure 1
        result = decoder.validate(INVALID_MISSING_ARGS)  # failure 2

        assert result.status == ValidationStatus.RETRY
        assert result.attempt == 2
        assert result.failures == 2
        assert result.retries_remaining == 0

    def test_retry_result_errors_describe_violations(self) -> None:
        """Collected errors are human-readable JSON Schema violation messages."""
        decoder = ConstrainedDecoder(TOOL_SCHEMA)
        result = decoder.validate(INVALID_MISSING_ARGS)

        # "args" is required — error must mention it
        combined_errors = " ".join(result.errors)
        assert "args" in combined_errors, (
            f"Expected error about missing 'args' property; got: {result.errors}"
        )

    def test_multiple_violations_all_reported(self) -> None:
        """All schema violations are collected, not just the first."""
        decoder = ConstrainedDecoder(TOOL_SCHEMA)
        # Both wrong type AND extra property violate the schema
        result = decoder.validate(INVALID_WRONG_TYPE)
        assert len(result.errors) >= 1

    def test_accepted_after_recovery_has_correct_attempt_number(self) -> None:
        """Attempt counter is 1-indexed and increments regardless of validity."""
        decoder = ConstrainedDecoder(TOOL_SCHEMA, max_retries=2)
        decoder.validate(INVALID_MISSING_ARGS)   # attempt 1 → RETRY
        result = decoder.validate(VALID_CALL)     # attempt 2 → ACCEPTED

        assert result.attempt == 2
        assert result.status == ValidationStatus.ACCEPTED


# --------------------------------------------------------------------------- #
# P1-AC5-d: Exception types and terminal-state guards                         #
# --------------------------------------------------------------------------- #

class TestExceptions:
    """ConstrainedDecodingError fields and DecoderTerminatedError guard."""

    def test_constrained_decoding_error_carries_required_fields(self) -> None:
        """ConstrainedDecodingError exposes tool_name, errors, total_failures."""
        decoder = ConstrainedDecoder(
            TOOL_SCHEMA,
            max_retries=0,
            tool_name="search_code",
        )
        with pytest.raises(ConstrainedDecodingError) as exc_info:
            decoder.validate(INVALID_MISSING_ARGS)

        exc = exc_info.value
        assert exc.tool_name == "search_code"
        assert exc.total_failures == 1
        assert len(exc.errors) >= 1
        assert isinstance(exc.errors[0], str)
        # Exception message is human-readable and mentions the tool name
        assert "search_code" in str(exc)

    def test_constrained_decoding_error_after_full_retry_sequence(self) -> None:
        """ConstrainedDecodingError.total_failures equals max_retries+1."""
        decoder = ConstrainedDecoder(
            TOOL_SCHEMA,
            max_retries=2,
            tool_name="code_edit",
        )
        decoder.validate(INVALID_MISSING_ARGS)  # failure 1
        decoder.validate(INVALID_MISSING_ARGS)  # failure 2

        with pytest.raises(ConstrainedDecodingError) as exc_info:
            decoder.validate(INVALID_MISSING_ARGS)  # failure 3 → FAILED

        assert exc_info.value.total_failures == 3
        assert exc_info.value.tool_name == "code_edit"

    def test_validate_on_accepted_decoder_raises_terminated_error(self) -> None:
        """Calling validate() on an ACCEPTED decoder raises DecoderTerminatedError."""
        decoder = ConstrainedDecoder(TOOL_SCHEMA)
        decoder.validate(VALID_CALL)
        assert decoder.state == DecoderState.ACCEPTED

        with pytest.raises(DecoderTerminatedError) as exc_info:
            decoder.validate(VALID_CALL)

        assert "ACCEPTED" in str(exc_info.value)

    def test_validate_on_failed_decoder_raises_terminated_error(self) -> None:
        """Calling validate() on a FAILED decoder raises DecoderTerminatedError."""
        decoder = ConstrainedDecoder(TOOL_SCHEMA, max_retries=0)

        with pytest.raises(ConstrainedDecodingError):
            decoder.validate(INVALID_MISSING_ARGS)

        assert decoder.state == DecoderState.FAILED

        # Second call on the terminal FAILED decoder
        with pytest.raises(DecoderTerminatedError) as exc_info:
            decoder.validate(VALID_CALL)

        assert "FAILED" in str(exc_info.value)

    def test_failed_state_does_not_raise_terminated_error_on_first_call(self) -> None:
        """Verify the guard only fires on the second call, not the failing call itself."""
        decoder = ConstrainedDecoder(TOOL_SCHEMA, max_retries=0)
        # First call raises ConstrainedDecodingError (not DecoderTerminatedError)
        with pytest.raises(ConstrainedDecodingError):
            decoder.validate(INVALID_MISSING_ARGS)


# --------------------------------------------------------------------------- #
# P1-AC5-e: Mandatory audit event on FAILED                                   #
# --------------------------------------------------------------------------- #

class TestAuditEvent:
    """FAILED state must fire a constrained_decode_fail audit record (ADR Б0.2)."""

    def test_failed_state_writes_constrained_decode_fail_audit_event(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """On FAILED: forge.audit emits manifest_event.v1 with all mandatory fields.

        Schema: forge.audit.manifest_event.v1
        Mandatory fields: tool_name, server_id, manifest_hash, action, reason, ts
        Action must be "constrained_decode_fail".
        """
        decoder = ConstrainedDecoder(
            TOOL_SCHEMA,
            max_retries=0,
            tool_name="search_code",
            server_id="spiffe://forge.local/mcp-gateway",
            manifest_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4",
        )

        with caplog.at_level(logging.WARNING, logger="forge.audit"):
            with pytest.raises(ConstrainedDecodingError):
                decoder.validate(INVALID_MISSING_ARGS)

        # Filter to forge.audit logger only
        audit_records = [r for r in caplog.records if r.name == "forge.audit"]
        assert len(audit_records) >= 1, (
            "No audit record emitted on FAILED state. "
            "ADR Б0.2: decode failures MUST be audited."
        )

        # Parse the JSON payload
        raw_msg = audit_records[-1].getMessage()  # last record is the FAILED event
        assert raw_msg.startswith("AUDIT "), f"Unexpected format: {raw_msg!r}"
        payload = json.loads(raw_msg[len("AUDIT "):])

        # Mandatory schema
        assert payload.get("schema") == "forge.audit.manifest_event.v1", (
            f"Wrong schema: {payload.get('schema')!r}"
        )
        # ADR P1-AC5: action must be "constrained_decode_fail"
        assert payload["action"] == "constrained_decode_fail", (
            f"Wrong action: {payload['action']!r}"
        )
        # Tool identification fields
        assert payload["tool_name"] == "search_code"
        assert payload["server_id"] == "spiffe://forge.local/mcp-gateway"
        assert payload["manifest_hash"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4"
        # Mandatory reason and timestamp
        assert "reason" in payload and payload["reason"], "Missing 'reason' field"
        assert "ts" in payload and isinstance(payload["ts"], (int, float)), (
            "Missing or non-numeric 'ts' field"
        )
        # Reason should mention failure count
        assert "1" in payload["reason"], (
            f"Reason should reference failure count; got: {payload['reason']!r}"
        )

    def test_retry_state_does_not_write_audit_event(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """RETRY state must NOT fire an audit event — auditing on FAILED only."""
        decoder = ConstrainedDecoder(TOOL_SCHEMA, max_retries=2)

        with caplog.at_level(logging.WARNING, logger="forge.audit"):
            decoder.validate(INVALID_MISSING_ARGS)   # RETRY — no audit event
            decoder.validate(INVALID_MISSING_ARGS)   # RETRY — no audit event

        audit_records = [r for r in caplog.records if r.name == "forge.audit"]
        constrained_audits = [
            r for r in audit_records
            if "constrained_decode_fail" in r.getMessage()
        ]
        assert len(constrained_audits) == 0, (
            f"Unexpected audit event emitted during RETRY state: {constrained_audits}"
        )

    def test_accepted_state_does_not_write_audit_event(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """ACCEPTED state must NOT fire any audit event."""
        decoder = ConstrainedDecoder(TOOL_SCHEMA)

        with caplog.at_level(logging.WARNING, logger="forge.audit"):
            decoder.validate(VALID_CALL)

        audit_records = [r for r in caplog.records if r.name == "forge.audit"]
        assert len(audit_records) == 0, (
            f"Unexpected audit event on ACCEPTED: {[r.getMessage() for r in audit_records]}"
        )


# --------------------------------------------------------------------------- #
# P1-AC5-f: reset() allows decoder reuse                                      #
# --------------------------------------------------------------------------- #

class TestReset:
    """reset() restores IDLE state without rebuilding Draft7Validator."""

    def test_reset_after_failed_restores_idle(self) -> None:
        """reset() on a FAILED decoder allows reuse for a new tool-call sequence."""
        decoder = ConstrainedDecoder(TOOL_SCHEMA, max_retries=1)
        decoder.validate(INVALID_MISSING_ARGS)        # RETRY
        with pytest.raises(ConstrainedDecodingError):
            decoder.validate(INVALID_MISSING_ARGS)    # FAILED
        assert decoder.state == DecoderState.FAILED

        decoder.reset()

        assert decoder.state == DecoderState.IDLE
        assert decoder.failures == 0
        assert decoder.retries_remaining == 1  # max_retries preserved

        # Decoder is fully functional again
        result = decoder.validate(VALID_CALL)
        assert result.status == ValidationStatus.ACCEPTED

    def test_reset_after_accepted_restores_idle(self) -> None:
        """reset() on an ACCEPTED decoder allows processing a second tool call."""
        decoder = ConstrainedDecoder(TOOL_SCHEMA)
        decoder.validate(VALID_CALL)
        assert decoder.state == DecoderState.ACCEPTED

        decoder.reset()

        assert decoder.state == DecoderState.IDLE
        assert decoder.failures == 0

        # Second sequence — retry then success
        decoder.validate(INVALID_MISSING_ARGS)
        result = decoder.validate(VALID_CALL)
        assert result.status == ValidationStatus.ACCEPTED

    def test_reset_mid_retry_sequence_resets_failure_count(self) -> None:
        """reset() during a RETRY sequence clears failures and retries_remaining."""
        decoder = ConstrainedDecoder(TOOL_SCHEMA, max_retries=2)
        decoder.validate(INVALID_MISSING_ARGS)  # failure 1, retries_remaining=1
        assert decoder.failures == 1

        decoder.reset()

        assert decoder.failures == 0
        assert decoder.retries_remaining == 2   # back to full budget


# --------------------------------------------------------------------------- #
# P1-AC5-g: Edge cases and introspection API                                  #
# --------------------------------------------------------------------------- #

class TestEdgeCases:
    """Edge cases, properties, and representation."""

    def test_max_attempts_is_max_retries_plus_one(self) -> None:
        """max_attempts = max_retries + 1 (ADR K=2 → 3 total attempts)."""
        assert ConstrainedDecoder(TOOL_SCHEMA, max_retries=2).max_attempts == 3
        assert ConstrainedDecoder(TOOL_SCHEMA, max_retries=0).max_attempts == 1
        assert ConstrainedDecoder(TOOL_SCHEMA, max_retries=5).max_attempts == 6

    def test_retries_remaining_decrements_with_failures(self) -> None:
        """retries_remaining decrements with each failure and never goes negative."""
        decoder = ConstrainedDecoder(TOOL_SCHEMA, max_retries=2)
        assert decoder.retries_remaining == 2

        decoder.validate(INVALID_MISSING_ARGS)
        assert decoder.retries_remaining == 1

        decoder.validate(INVALID_MISSING_ARGS)
        assert decoder.retries_remaining == 0

    def test_repr_reflects_current_state(self) -> None:
        """__repr__ includes tool name, state, and failure counts."""
        decoder = ConstrainedDecoder(
            TOOL_SCHEMA, tool_name="search_code", max_retries=2
        )
        repr_str = repr(decoder)
        assert "search_code" in repr_str
        assert "IDLE" in repr_str

        decoder.validate(INVALID_MISSING_ARGS)
        repr_str_retry = repr(decoder)
        assert "RETRY" in repr_str_retry

    def test_different_invalid_calls_each_produce_errors(self) -> None:
        """Each invalid call on a RETRY decoder produces a fresh error list."""
        decoder = ConstrainedDecoder(TOOL_SCHEMA, max_retries=2)

        r1 = decoder.validate(INVALID_MISSING_ARGS)    # missing "args"
        r2 = decoder.validate(INVALID_EXTRA_PROP)      # extra "inject" property

        # Both produce non-empty error lists describing the violation
        assert len(r1.errors) >= 1
        assert len(r2.errors) >= 1
        # The errors describe the CURRENT call's violations, not accumulated ones
        assert "args" in " ".join(r1.errors)
