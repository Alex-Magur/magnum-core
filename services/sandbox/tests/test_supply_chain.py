import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path
from sandbox.supply_chain import ManifestVerifier, VerificationResult


@pytest.fixture
def verifier():
    return ManifestVerifier()


def test_verify_signature_success(verifier):
    with patch("sandbox.supply_chain.load_pem_public_key") as mock_load:
        mock_key = MagicMock()
        from cryptography.hazmat.primitives.asymmetric import ec
        # Mock as EllipticCurvePublicKey
        mock_key.__class__ = ec.EllipticCurvePublicKey
        mock_load.return_value = mock_key
        
        # Signature verification succeeds (no exception)
        mock_key.verify.return_value = None
        
        res = verifier.verify_signature("sha256:abc", b"sig", b"pubkey")
        assert res is True


def test_verify_signature_failure(verifier):
    with patch("sandbox.supply_chain.load_pem_public_key") as mock_load:
        mock_key = MagicMock()
        from cryptography.hazmat.primitives.asymmetric import ec
        mock_key.__class__ = ec.EllipticCurvePublicKey
        mock_load.return_value = mock_key
        
        from cryptography.exceptions import InvalidSignature
        mock_key.verify.side_effect = InvalidSignature()
        
        res = verifier.verify_signature("sha256:abc", b"sig", b"pubkey")
        assert res is False


def test_cvss_allowlist_gate(verifier, tmp_path):
    allowlist_file = tmp_path / "allowlist.yaml"
    
    # Low CVSS passes automatically
    assert verifier.check_cve_allowlist("CVE-1", 5.0, allowlist_file) is True
    
    # High CVSS fails if no allowlist
    assert verifier.check_cve_allowlist("CVE-CRIT", 9.5, allowlist_file) is False
    
    # High CVSS passes if in allowlist (simple list)
    allowlist_file.write_text("allowed_cves: [CVE-CRIT]")
    assert verifier.check_cve_allowlist("CVE-CRIT", 9.5, allowlist_file) is True
    
    # High CVSS passes if in allowlist (dict format)
    allowlist_file.write_text("allowed_cves: [{cve_id: CVE-CRIT-2}]")
    assert verifier.check_cve_allowlist("CVE-CRIT-2", 9.1, allowlist_file) is True


def test_verify_image_orchestration(verifier):
    with patch.object(verifier, "verify_signature", return_value=True), \
         patch.object(verifier, "check_cve_allowlist", return_value=True):
        
        res = verifier.verify_image(
            image_ref="ubuntu:latest",
            manifest_digest="sha256:...",
            signature=b"...",
            public_key_pem=b"...",
            cve_scan_results=[{"cve_id": "CVE-X", "cvss_score": 9.2}],
            allowlist_path="/tmp/allow"
        )
        assert res.allowed is True
        assert res.blocked_reason is None
