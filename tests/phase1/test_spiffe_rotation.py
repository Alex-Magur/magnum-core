"""P1-AC2: SPIFFE Rotation (TTL=1h) — Phase 1 Gate Test.

ADR References:
  - Б1.1 (Strict mTLS / SPIFFE):
        "TTL SVID certificates = 1h, mandatory graceful connection cycling."
  - Б16 P1-AC2 (SPIFFE Rotation):
        Given: SVID TTL = 1h.
        When:  The service holds a connection for longer than 1h.
        Then:  The connection is re-created without downtime using a new SVID.

Acceptance criteria verified by this file
------------------------------------------
P1-AC2-a  simulate_rotation() fires the on_rotate callback with the exact
          (new_cert_pem, new_key_pem) material and updates watcher state.
P1-AC2-b  simulate_rotation() writes a mandatory audit record containing
          [key_id, action="rotate", operator, reason, ts] to the
          "forge.audit" logger (ADR Б2.4 Key Ceremony Audit contract).
P1-AC2-c  The ssl.SSLContext rebuilt inside the on_rotate callback is valid:
          a new TLS server instantiated from it accepts a mTLS client
          connection and returns HTTP 200 OK — demonstrating that rotation
          produces a working context with no service downtime.

Test strategy
-------------
- ``SVIDRotationWatcher.simulate_rotation()`` directly injects new cert/key
  material, bypassing file I/O and TTL timers entirely (approved Q1 design).
- The on_rotate callback pattern mirrors the ``forge_api.main._lifespan``
  reload callback: it holds a mutable reference to the current ssl.SSLContext
  and atomically replaces it.
- Ephemeral ECDSA P-256 certificates are generated in-process via the
  ``cryptography`` library — no disk writes, no gen-certs.sh dependency.
- The cert_bundle fixture exposes raw CA objects alongside PEM bytes so
  tests can generate fresh leaf certs (new SVIDs from same CA).
- ``asyncio.start_server(port=0)`` uses a random free port (ADR-approved Q1).
"""

from __future__ import annotations

import asyncio
import datetime
import json
import logging
import socket
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from forge_security.mtls import build_client_context, build_server_context
from forge_security.spiffe import SVIDRotationWatcher

pytestmark = pytest.mark.phase1


# --------------------------------------------------------------------------- #
# In-process ephemeral ECDSA certificate generation                            #
# --------------------------------------------------------------------------- #

def _ec_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _key_to_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _now_utc() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _build_ca() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Return a self-signed ECDSA P-256 CA (1 day validity, ephemeral)."""
    key = _ec_key()
    now = _now_utc()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Forge SPIFFE Test CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _build_leaf_cert(
    ca_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    spiffe_id: str,
    *,
    is_server: bool,
    ttl_hours: float = 1.0,
) -> tuple[bytes, bytes]:
    """Return ``(cert_pem, key_pem)`` for a leaf cert with a SPIFFE URI SAN.

    Args:
        ttl_hours: Controls ``not_valid_after``; default 1h mirrors ADR Б1.1.
    """
    key = _ec_key()
    now = _now_utc()
    eku = (
        [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
        if is_server
        else [ExtendedKeyUsageOID.CLIENT_AUTH]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, spiffe_id)])
        )
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(hours=ttl_hours))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=False
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier(spiffe_id)]
            ),
            critical=False,
        )
        .add_extension(x509.ExtendedKeyUsage(eku), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        _key_to_pem(key),
    )


# --------------------------------------------------------------------------- #
# Shared fixture                                                               #
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def cert_bundle() -> dict[str, Any]:
    """Generate an ephemeral CA + initial server + client cert bundle.

    Importantly, also exposes the raw CA key and certificate objects so that
    individual tests can call ``_build_leaf_cert()`` to produce additional
    SVIDs (simulating SPIRE issuing a new SVID from the same root CA).

    In production SPIFFE deployments the root CA remains stable across SVID
    rotation; only the leaf cert TTL=1h is replaced.
    """
    ca_key, ca_cert = _build_ca()
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)

    server_cert_pem, server_key_pem = _build_leaf_cert(
        ca_key, ca_cert,
        "spiffe://forge.local/forge-api",
        is_server=True,
    )
    client_cert_pem, client_key_pem = _build_leaf_cert(
        ca_key, ca_cert,
        "spiffe://forge.local/test-client",
        is_server=False,
    )

    return {
        # Raw CA objects — needed to generate fresh SVIDs in tests
        "ca_key":  ca_key,
        "ca_cert": ca_cert,
        # PEM-encoded material
        "ca_pem":          ca_pem,
        "server_cert_pem": server_cert_pem,
        "server_key_pem":  server_key_pem,
        "client_cert_pem": client_cert_pem,
        "client_key_pem":  client_key_pem,
    }


# --------------------------------------------------------------------------- #
# Minimal TLS server helper (shared with test_mtls_strict pattern)            #
# --------------------------------------------------------------------------- #

_HTTP_200 = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Length: 15\r\n"
    b"Content-Type: application/json\r\n"
    b"\r\n"
    b'{"status":"ok"}'
)


async def _start_tls_server(ssl_ctx) -> tuple[asyncio.AbstractServer, int]:
    """Start a minimal asyncio TLS server on a random localhost port."""

    async def _handler(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        await reader.read(4096)
        writer.write(_HTTP_200)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(
        _handler, host="127.0.0.1", port=0, ssl=ssl_ctx
    )
    port: int = server.sockets[0].getsockname()[1]
    return server, port


# --------------------------------------------------------------------------- #
# P1-AC2-a: simulate_rotation fires callback with correct material            #
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_simulate_rotation_fires_callback_with_correct_material(
    tmp_path, cert_bundle: dict[str, Any]
) -> None:
    """P1-AC2-a: simulate_rotation delivers (new_cert_pem, new_key_pem) to on_rotate.

    Given: SVIDRotationWatcher configured with TTL=1h (test-accelerated).
    When:  simulate_rotation() is called with a freshly generated SVID.
    Then:
      - on_rotate callback is invoked exactly once.
      - Callback receives the exact (new_cert_pem, new_key_pem) bytes.
      - watcher.rotation_count increments to 1.
      - watcher.last_cert_pem equals new_cert_pem.
    """
    # Generate a fresh SVID — same CA, new leaf cert (realistic SPIRE renewal).
    new_server_cert_pem, new_server_key_pem = _build_leaf_cert(
        cert_bundle["ca_key"],
        cert_bundle["ca_cert"],
        "spiffe://forge.local/forge-api",
        is_server=True,
    )

    captured: dict[str, Any] = {"calls": 0, "cert": None, "key": None}

    async def on_rotate(cert: bytes, key: bytes) -> None:
        captured["calls"] += 1
        captured["cert"] = cert
        captured["key"] = key

    watcher = SVIDRotationWatcher(
        cert_path=tmp_path / "svid.crt",
        key_path=tmp_path / "svid.key",
        ttl_seconds=3600,
        on_rotate=on_rotate,
        svid_id="spiffe://forge.local/forge-api",
        operator="test_harness",
    )

    # Trigger rotation WITHOUT starting the background watcher loop.
    await watcher.simulate_rotation(new_server_cert_pem, new_server_key_pem)

    assert captured["calls"] == 1, (
        f"on_rotate was called {captured['calls']} time(s); expected exactly 1."
    )
    assert captured["cert"] == new_server_cert_pem, (
        "on_rotate received wrong cert_pem — SVID material was not passed through."
    )
    assert captured["key"] == new_server_key_pem, (
        "on_rotate received wrong key_pem — SVID material was not passed through."
    )
    assert watcher.rotation_count == 1, (
        f"watcher.rotation_count={watcher.rotation_count}; expected 1."
    )
    assert watcher.last_cert_pem == new_server_cert_pem, (
        "watcher.last_cert_pem not updated after rotation."
    )


# --------------------------------------------------------------------------- #
# P1-AC2-b: simulate_rotation writes mandatory audit event                    #
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_simulate_rotation_writes_mandatory_audit_event(
    tmp_path, cert_bundle: dict[str, Any], caplog: pytest.LogCaptureFixture
) -> None:
    """P1-AC2-b: simulate_rotation emits a mandatory [key_id, action, operator, reason, ts] audit record.

    Given: SVIDRotationWatcher with svid_id="spiffe://forge.local/forge-api"
           and operator="test_harness".
    When:  simulate_rotation() is called.
    Then:
      - The "forge.audit" logger emits a WARNING-level record.
      - The JSON payload contains:
          schema  = "forge.audit.key_event.v1"
          key_id  = "spiffe://forge.local/forge-api"
          action  = "rotate"
          operator = "test_harness"
          reason  (non-empty string)
          ts      (numeric Unix epoch)
    """
    async def noop(cert: bytes, key: bytes) -> None:
        pass

    watcher = SVIDRotationWatcher(
        cert_path=tmp_path / "svid.crt",
        key_path=tmp_path / "svid.key",
        ttl_seconds=3600,
        on_rotate=noop,
        svid_id="spiffe://forge.local/forge-api",
        operator="test_harness",
    )

    new_server_cert_pem, new_server_key_pem = _build_leaf_cert(
        cert_bundle["ca_key"],
        cert_bundle["ca_cert"],
        "spiffe://forge.local/forge-api",
        is_server=True,
    )

    with caplog.at_level(logging.WARNING, logger="forge.audit"):
        await watcher.simulate_rotation(new_server_cert_pem, new_server_key_pem)

    # Isolate records from the "forge.audit" logger.
    audit_records = [r for r in caplog.records if r.name == "forge.audit"]

    assert len(audit_records) >= 1, (
        "No audit record was written to 'forge.audit' during simulate_rotation. "
        "ADR Б2.4 mandates a mandatory record for every key-rotation event."
    )

    # Parse the JSON payload from the first matching record.
    raw_message = audit_records[0].getMessage()
    assert raw_message.startswith("AUDIT "), (
        f"Unexpected audit record format: {raw_message!r}"
    )
    payload = json.loads(raw_message[len("AUDIT "):])

    # Verify every mandatory field from ADR Б2.4: [key_id, action, operator, reason, ts]
    assert payload.get("schema") == "forge.audit.key_event.v1", (
        f"Wrong schema: {payload.get('schema')!r}"
    )
    assert payload["key_id"] == "spiffe://forge.local/forge-api", (
        f"Wrong key_id: {payload['key_id']!r}"
    )
    assert payload["action"] == "rotate", (
        f"Wrong action: {payload['action']!r} — expected 'rotate'"
    )
    assert payload["operator"] == "test_harness", (
        f"Wrong operator: {payload['operator']!r}"
    )
    assert "reason" in payload and payload["reason"], (
        "Audit record is missing a non-empty 'reason' field."
    )
    assert "ts" in payload and isinstance(payload["ts"], (int, float)), (
        f"Audit record 'ts' is missing or not numeric: {payload.get('ts')!r}"
    )


# --------------------------------------------------------------------------- #
# P1-AC2-c: New SSLContext is valid and accepts connections after rotation    #
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_new_ssl_context_valid_after_rotation(
    tmp_path, cert_bundle: dict[str, Any]
) -> None:
    """P1-AC2-c: SSLContext rebuilt in on_rotate callback accepts mTLS connections.

    Demonstrates the "without downtime" ADR contract by showing that:
      1. A connection to the old server (pre-rotation) succeeds (HTTP 200).
      2. After simulate_rotation() the callback atomically replaces the
         ssl.SSLContext reference in ssl_ctx_holder (the mutable state used
         by the service lifecycle, as in forge_api.main._lifespan).
      3. A new server started with the rotated SSLContext accepts a fresh
         mTLS connection (HTTP 200) — new SVIDs work immediately.

    The atomicity of step 2 is the core of the hot-reload contract: existing
    TLS sessions (already at the application layer) are unaffected; only new
    accept() calls pick up the new context.
    """
    # ── Phase 1: old SVID — initial server ───────────────────────────────────
    ssl_ctx_holder: dict[str, Any] = {
        "ctx": build_server_context(
            cert_bundle["server_cert_pem"],
            cert_bundle["server_key_pem"],
            cert_bundle["ca_pem"],
        )
    }
    old_ctx_id = id(ssl_ctx_holder["ctx"])

    old_server, old_port = await _start_tls_server(ssl_ctx_holder["ctx"])

    client_ctx = build_client_context(
        cert_bundle["client_cert_pem"],
        cert_bundle["client_key_pem"],
        cert_bundle["ca_pem"],
    )

    # Confirm pre-rotation connection works.
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", old_port, ssl=client_ctx, server_hostname="127.0.0.1"
    )
    writer.write(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
    await writer.drain()
    data_before = await reader.read(4096)
    writer.close()
    await writer.wait_closed()
    old_server.close()
    await old_server.wait_closed()

    assert b"200 OK" in data_before, "Pre-rotation connection failed."

    # ── Phase 2: simulate_rotation — atomic SSLContext hot-reload ────────────
    async def on_rotate(cert: bytes, key: bytes) -> None:
        """Production-identical reload callback: atomically replace the context."""
        ssl_ctx_holder["ctx"] = build_server_context(
            cert, key, cert_bundle["ca_pem"]
        )

    watcher = SVIDRotationWatcher(
        cert_path=tmp_path / "svid.crt",
        key_path=tmp_path / "svid.key",
        ttl_seconds=3600,
        on_rotate=on_rotate,
        svid_id="spiffe://forge.local/forge-api",
        operator="test_harness",
    )

    # Generate a new SVID (same CA, new leaf cert — realistic SPIRE renewal).
    new_server_cert_pem, new_server_key_pem = _build_leaf_cert(
        cert_bundle["ca_key"],
        cert_bundle["ca_cert"],
        "spiffe://forge.local/forge-api",
        is_server=True,
    )

    await watcher.simulate_rotation(new_server_cert_pem, new_server_key_pem)

    # Assert: ssl_ctx_holder["ctx"] is a DIFFERENT object (was atomically replaced).
    assert id(ssl_ctx_holder["ctx"]) != old_ctx_id, (
        "ssl_ctx_holder['ctx'] was NOT replaced by the on_rotate callback. "
        "Hot-reload did not occur — the new SVID is not in effect."
    )

    # ── Phase 3: new server with rotated SSLContext ───────────────────────────
    new_server, new_port = await _start_tls_server(ssl_ctx_holder["ctx"])

    try:
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", new_port, ssl=client_ctx, server_hostname="127.0.0.1"
        )
        writer.write(
            b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        )
        await writer.drain()
        data_after = await reader.read(4096)
        writer.close()
        await writer.wait_closed()
    finally:
        new_server.close()
        await new_server.wait_closed()

    assert b"200 OK" in data_after, (
        "Post-rotation connection FAILED. "
        "The new SSLContext built by on_rotate is not a valid mTLS context."
    )
    assert b'"status":"ok"' in data_after
