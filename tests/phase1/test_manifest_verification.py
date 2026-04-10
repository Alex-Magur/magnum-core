"""P1-AC6: Tool Manifest Verification — Phase 1 Gate Test.

ADR References:
  - Б2.2 (Immutable Tool Manifest, Pinning & Container SBOM):
        "Server Identity Pinning: tool is bound by
         tool_name + server_id (SPIFFE ID) + manifest_hash."
  - Б16 P1-AC6 (Tool Verification):
        When manifest signature is invalid:
          → tool = QUARANTINED
          → subsequent calls are blocked immediately
          → alert fires (audit log event with action="quarantine")

Acceptance criteria verified by this file
------------------------------------------
P1-AC6-a  Valid ECDSA P-256 signature → VerificationResult(status=OK),
          verify_ok audit event written.
P1-AC6-b  Invalid/corrupt signature → ManifestVerificationError raised,
          tool quarantined in registry, quarantine audit event written.
P1-AC6-c  Subsequent verify() call on a quarantined tool raises
          ToolQuarantinedError immediately — no signature check attempted.
P1-AC6-d  ToolRegistry.release() clears quarantine; tool is verifiable again.
P1-AC6-e  Canonicalization correctness: NUL-byte separator prevents
          field-confusion attacks; a signature for (A, B, C) is invalid
          for a triplet that concatenates to the same bytes without NULs.
P1-AC6-f  Wrong public key → ManifestVerificationError (cross-key confusion).
P1-AC6-g  Tampered manifest_hash → ManifestVerificationError (identity pinning).
P1-AC6-h  Malformed PEM → ValueError (fail fast at key loading).
P1-AC6-i  Registry isolation: each ToolVerifier with its own ToolRegistry
          instance is independent — quarantine in one does not affect another.

Test strategy
-------------
- All keys generated in-process using cryptography.  No file I/O.
- Each test passes a fresh ToolRegistry() to avoid cross-test contamination
  from the module-level ToolVerifier._default_registry class variable.
- Canonical digest is independently computed in tests (same formula as
  _build_signed_payload) to confirm the signing contract.
"""

from __future__ import annotations

import hashlib
import json
import logging

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from forge_security.audit.logger import write_manifest_event
from forge_security.manifest.verifier import (
    ManifestVerificationError,
    ToolManifest,
    ToolQuarantinedError,
    ToolRegistry,
    ToolVerifier,
    VerificationStatus,
)

pytestmark = pytest.mark.phase1


# --------------------------------------------------------------------------- #
# Signing helpers — mirror the canonical payload of _build_signed_payload     #
# --------------------------------------------------------------------------- #

_NUL = b"\x00"


def _ec_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _public_key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _canonical_digest(tool_name: str, server_id: str, manifest_hash: str) -> bytes:
    """Reproduce the canonical signing digest from verifier._build_signed_payload."""
    raw = (
        tool_name.encode()   + _NUL
        + server_id.encode() + _NUL
        + manifest_hash.encode()
    )
    return hashlib.sha256(raw).digest()


def _sign(
    key: ec.EllipticCurvePrivateKey,
    tool_name: str,
    server_id: str,
    manifest_hash: str,
) -> bytes:
    """Sign the canonical payload.  Mirrors ToolVerifier._dispatch_verify path."""
    digest = _canonical_digest(tool_name, server_id, manifest_hash)
    return key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))


def _make_manifest(
    key: ec.EllipticCurvePrivateKey,
    tool_name: str = "search_code",
    server_id: str = "spiffe://forge.local/mcp-gateway",
    manifest_hash: str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4",
) -> ToolManifest:
    """Build a correctly-signed ToolManifest."""
    return ToolManifest(
        tool_name=tool_name,
        server_id=server_id,
        manifest_hash=manifest_hash,
        signature=_sign(key, tool_name, server_id, manifest_hash),
        public_key_pem=_public_key_pem(key),
    )


# --------------------------------------------------------------------------- #
# P1-AC6-a: Valid signature is accepted                                        #
# --------------------------------------------------------------------------- #

class TestValidSignature:
    """A correctly signed manifest must be accepted with status=OK."""

    def test_valid_ecdsa_signature_returns_ok(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """P1-AC6-a: Valid ECDSA P-256 signature → VerificationResult(status=OK)."""
        key = _ec_key()
        manifest = _make_manifest(key)
        verifier = ToolVerifier(registry=ToolRegistry())

        with caplog.at_level(logging.WARNING, logger="forge.audit"):
            result = verifier.verify(manifest)

        assert result.status == VerificationStatus.OK
        assert result.tool_name == "search_code"
        assert result.manifest_hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4"

    def test_valid_signature_writes_verify_ok_audit_event(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """P1-AC6-a: Successful verification emits verify_ok audit record."""
        key = _ec_key()
        manifest = _make_manifest(key, tool_name="code_edit")
        verifier = ToolVerifier(registry=ToolRegistry())

        with caplog.at_level(logging.WARNING, logger="forge.audit"):
            verifier.verify(manifest)

        audit_records = [r for r in caplog.records if r.name == "forge.audit"]
        assert len(audit_records) >= 1

        payloads = [
            json.loads(r.getMessage()[len("AUDIT "):])
            for r in audit_records
            if r.getMessage().startswith("AUDIT ")
        ]
        verify_ok_records = [p for p in payloads if p.get("action") == "verify_ok"]

        assert len(verify_ok_records) == 1, (
            f"Expected exactly one verify_ok audit record; got: {payloads}"
        )
        record = verify_ok_records[0]
        assert record["schema"] == "forge.audit.manifest_event.v1"
        assert record["tool_name"] == "code_edit"
        assert record["action"] == "verify_ok"
        assert record["reason"] == "signature_valid"
        assert "ts" in record and isinstance(record["ts"], (int, float))

    def test_valid_signature_does_not_quarantine_tool(self) -> None:
        """Successful verification must NOT quarantine the tool."""
        key = _ec_key()
        manifest = _make_manifest(key)
        registry = ToolRegistry()
        verifier = ToolVerifier(registry=registry)

        verifier.verify(manifest)

        assert not registry.is_quarantined("search_code")


# --------------------------------------------------------------------------- #
# P1-AC6-b: Invalid signature quarantines and alerts                          #
# --------------------------------------------------------------------------- #

class TestInvalidSignature:
    """An invalid signature must quarantine the tool and fire an audit alert."""

    def test_invalid_signature_raises_manifest_verification_error(self) -> None:
        """P1-AC6-b: Corrupted signature bytes → ManifestVerificationError."""
        key = _ec_key()
        manifest = ToolManifest(
            tool_name="search_code",
            server_id="spiffe://forge.local/mcp-gateway",
            manifest_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4",
            signature=b"not-a-valid-der-signature",    # deliberately corrupt
            public_key_pem=_public_key_pem(key),
        )
        verifier = ToolVerifier(registry=ToolRegistry())

        with pytest.raises(ManifestVerificationError) as exc_info:
            verifier.verify(manifest)

        exc = exc_info.value
        assert exc.tool_name == "search_code"
        assert "search_code" in str(exc)

    def test_invalid_signature_quarantines_tool(self) -> None:
        """P1-AC6-b: After ManifestVerificationError, tool is in QUARANTINED state."""
        key = _ec_key()
        manifest = ToolManifest(
            tool_name="evil_tool",
            server_id="spiffe://forge.local/mcp-gateway",
            manifest_hash="aaaa",
            signature=b"bad",
            public_key_pem=_public_key_pem(key),
        )
        registry = ToolRegistry()
        verifier = ToolVerifier(registry=registry)

        with pytest.raises(ManifestVerificationError):
            verifier.verify(manifest)

        assert registry.is_quarantined("evil_tool"), (
            "Tool was not quarantined after ManifestVerificationError. "
            "ADR P1-AC6: invalid signature MUST quarantine the tool."
        )

    def test_invalid_signature_writes_quarantine_audit_event(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """P1-AC6-b: Invalid signature emits quarantine audit record (alert fires)."""
        key = _ec_key()
        manifest = ToolManifest(
            tool_name="bad_tool",
            server_id="spiffe://forge.local/mcp-server",
            manifest_hash="deadbeef",
            signature=b"garbage",
            public_key_pem=_public_key_pem(key),
        )
        verifier = ToolVerifier(registry=ToolRegistry())

        with caplog.at_level(logging.WARNING, logger="forge.audit"):
            with pytest.raises(ManifestVerificationError):
                verifier.verify(manifest)

        audit_records = [r for r in caplog.records if r.name == "forge.audit"]
        payloads = [
            json.loads(r.getMessage()[len("AUDIT "):])
            for r in audit_records
            if r.getMessage().startswith("AUDIT ")
        ]
        quarantine_events = [p for p in payloads if p.get("action") == "quarantine"]

        assert len(quarantine_events) >= 1, (
            "No quarantine audit event emitted on invalid signature. "
            "ADR P1-AC6: 'alert fires' = mandatory quarantine audit record."
        )
        event = quarantine_events[0]
        assert event["schema"] == "forge.audit.manifest_event.v1"
        assert event["tool_name"] == "bad_tool"
        assert event["server_id"] == "spiffe://forge.local/mcp-server"
        assert event["manifest_hash"] == "deadbeef"
        assert event["reason"] == "invalid_signature"
        assert "ts" in event


# --------------------------------------------------------------------------- #
# P1-AC6-c: Quarantined tool is immediately blocked                           #
# --------------------------------------------------------------------------- #

class TestQuarantinedToolBlocked:
    """Subsequent calls to a quarantined tool raise ToolQuarantinedError immediately."""

    def test_quarantined_tool_raises_on_next_verify(self) -> None:
        """P1-AC6-c: After quarantine, verify() raises ToolQuarantinedError immediately."""
        key = _ec_key()
        registry = ToolRegistry()
        verifier = ToolVerifier(registry=registry)

        # Invalidate signature → tool quarantined
        bad_manifest = ToolManifest(
            tool_name="malicious_tool",
            server_id="spiffe://forge.local/mcp-gateway",
            manifest_hash="cafebabe",
            signature=b"invalid",
            public_key_pem=_public_key_pem(key),
        )
        with pytest.raises(ManifestVerificationError):
            verifier.verify(bad_manifest)

        assert registry.is_quarantined("malicious_tool")

        # Even with a valid signature now, the tool must be blocked
        valid_manifest = _make_manifest(
            key, tool_name="malicious_tool", manifest_hash="cafebabe"
        )
        with pytest.raises(ToolQuarantinedError) as exc_info:
            verifier.verify(valid_manifest)

        assert exc_info.value.tool_name == "malicious_tool"
        assert "malicious_tool" in str(exc_info.value)

    def test_pre_quarantined_tool_blocked_before_any_verify(self) -> None:
        """P1-AC6-c: A tool quarantined directly via registry is also blocked."""
        registry = ToolRegistry()
        registry.quarantine("pre_blocked_tool")
        verifier = ToolVerifier(registry=registry)
        key = _ec_key()
        manifest = _make_manifest(key, tool_name="pre_blocked_tool")

        with pytest.raises(ToolQuarantinedError):
            verifier.verify(manifest)


# --------------------------------------------------------------------------- #
# P1-AC6-d: Release restores verifiability                                    #
# --------------------------------------------------------------------------- #

class TestRegistryRelease:
    """ToolRegistry.release() clears quarantine; tool can be verified again."""

    def test_release_allows_subsequent_verification(self) -> None:
        """P1-AC6-d: After release(), a valid signature is accepted again."""
        registry = ToolRegistry()
        registry.quarantine("temp_quarantined")

        # Confirm blocked
        verifier = ToolVerifier(registry=registry)
        key = _ec_key()
        with pytest.raises(ToolQuarantinedError):
            verifier.verify(_make_manifest(key, tool_name="temp_quarantined"))

        # Release
        registry.release("temp_quarantined")
        assert not registry.is_quarantined("temp_quarantined")

        # Verify again — should succeed with valid signature
        result = verifier.verify(_make_manifest(key, tool_name="temp_quarantined"))
        assert result.status == VerificationStatus.OK

    def test_release_nonexistent_tool_is_idempotent(self) -> None:
        """release() on a tool that was never quarantined is a safe no-op."""
        registry = ToolRegistry()
        registry.release("never_quarantined")  # must not raise
        assert not registry.is_quarantined("never_quarantined")


# --------------------------------------------------------------------------- #
# P1-AC6-e: NUL-byte canonicalization prevents field-confusion attacks        #
# --------------------------------------------------------------------------- #

class TestCanonicalization:
    """The NUL-byte separator prevents length-extension/confusion attacks."""

    def test_nul_separation_prevents_field_confusion(self) -> None:
        """P1-AC6-e: Signature for (abc, def, ...) ≠ signature for (ab, cdef, ...).

        Without NUL separators:
          "abc" + "def" = "abcdef"
          "ab"  + "cdef" = "abcdef"   ← SAME — confusion attack!

        With NUL separators:
          "abc" + NUL + "def" = "abc\\x00def"
          "ab"  + NUL + "cdef" = "ab\\x00cdef"  ← DIFFERENT — secure!
        """
        key = _ec_key()

        # Triplet A: ("a_b", "c", hash) — when concatenated naively: "a_bc..."
        # Triplet B: ("a", "b_c", hash) — when concatenated naively: "a_bc..."  (same!)
        # With NUL: "a_b\x00c\x00..." vs "a\x00b_c\x00..." — different digests.
        SHARED_HASH = "abc123"

        # Sign triplet A
        manifest_a = ToolManifest(
            tool_name="search",
            server_id="code",
            manifest_hash=SHARED_HASH,
            signature=_sign(key, "search", "code", SHARED_HASH),
            public_key_pem=_public_key_pem(key),
        )

        # Attempt to use triplet A's signature for triplet B (field boundary shifted)
        manifest_b_with_a_sig = ToolManifest(
            tool_name="searchcode",    # "search" + "code" concatenated — same naive string
            server_id="",              # empty server_id
            manifest_hash=SHARED_HASH,
            signature=manifest_a.signature,   # reuse triplet A's signature
            public_key_pem=_public_key_pem(key),
        )

        verifier_a = ToolVerifier(registry=ToolRegistry())
        verifier_b = ToolVerifier(registry=ToolRegistry())

        # Triplet A succeeds
        result_a = verifier_a.verify(manifest_a)
        assert result_a.status == VerificationStatus.OK

        # Triplet B with A's signature MUST fail (NUL prevents confusion)
        with pytest.raises(ManifestVerificationError):
            verifier_b.verify(manifest_b_with_a_sig)

    def test_tampered_manifest_hash_fails(self) -> None:
        """P1-AC6-e: Changing manifest_hash invalidates the signature (identity pinning)."""
        key = _ec_key()
        original_hash = "legitimate_hash_abc123"
        tampered_hash = "tampered_hash_xyz789"

        # Sign original manifest
        manifest = ToolManifest(
            tool_name="search_code",
            server_id="spiffe://forge.local/mcp-gateway",
            manifest_hash=tampered_hash,          # tampered — not what was signed
            signature=_sign(key, "search_code", "spiffe://forge.local/mcp-gateway", original_hash),
            public_key_pem=_public_key_pem(key),
        )
        verifier = ToolVerifier(registry=ToolRegistry())

        with pytest.raises(ManifestVerificationError):
            verifier.verify(manifest)


# --------------------------------------------------------------------------- #
# P1-AC6-f/g/h: Cross-key confusion, malformed PEM, registry isolation       #
# --------------------------------------------------------------------------- #

class TestSecurityBoundaries:
    """Additional security boundary tests."""

    def test_signature_from_different_key_fails(self) -> None:
        """P1-AC6-f: Signature produced by key_A cannot be verified with key_B."""
        key_a = _ec_key()
        key_b = _ec_key()

        # Sign with key_a, present key_b as the verifying key
        manifest = ToolManifest(
            tool_name="search_code",
            server_id="spiffe://forge.local/mcp-gateway",
            manifest_hash="abc123",
            signature=_sign(key_a, "search_code", "spiffe://forge.local/mcp-gateway", "abc123"),
            public_key_pem=_public_key_pem(key_b),   # wrong key
        )
        verifier = ToolVerifier(registry=ToolRegistry())

        with pytest.raises(ManifestVerificationError):
            verifier.verify(manifest)

    def test_malformed_pem_raises_value_error(self) -> None:
        """P1-AC6-h: Garbage PEM bytes raise ValueError — fail fast at key loading."""
        manifest = ToolManifest(
            tool_name="search_code",
            server_id="spiffe://forge.local/mcp-gateway",
            manifest_hash="abc123",
            signature=b"sig",
            public_key_pem=b"-----NOT A REAL PEM-----",
        )
        verifier = ToolVerifier(registry=ToolRegistry())

        with pytest.raises(ValueError, match="Cannot load public key"):
            verifier.verify(manifest)

    def test_registry_isolation_between_verifier_instances(self) -> None:
        """P1-AC6-i: Quarantine in one verifier's registry does not affect another."""
        registry_a = ToolRegistry()
        registry_b = ToolRegistry()

        registry_a.quarantine("shared_tool")
        assert registry_a.is_quarantined("shared_tool")
        assert not registry_b.is_quarantined("shared_tool")

        # verifier_b can verify shared_tool even though verifier_a quarantined it
        key = _ec_key()
        verifier_b = ToolVerifier(registry=registry_b)
        result = verifier_b.verify(_make_manifest(key, tool_name="shared_tool"))
        assert result.status == VerificationStatus.OK

    def test_all_quarantined_snapshot_is_immutable(self) -> None:
        """ToolRegistry.all_quarantined() returns a frozen snapshot."""
        registry = ToolRegistry()
        registry.quarantine("tool_x")
        registry.quarantine("tool_y")

        snapshot = registry.all_quarantined()
        assert isinstance(snapshot, frozenset)
        assert "tool_x" in snapshot
        assert "tool_y" in snapshot

        # Mutating registry after snapshot does not affect snapshot
        registry.release("tool_x")
        assert "tool_x" in snapshot          # snapshot unchanged
        assert not registry.is_quarantined("tool_x")  # live state updated
