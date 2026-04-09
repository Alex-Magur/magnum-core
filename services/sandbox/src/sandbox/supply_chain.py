"""sandbox.supply_chain — Container Supply Chain Verification.

ADR Блок 2.2: Dual-level verification enforcing image provenance signatures
and strict CVE gating rules before execution.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key

logger = logging.getLogger(__name__)

# ADR 2.2: CRITICAL (CVSS >= 9.0)
_CVSS_CRITICAL_THRESHOLD = 9.0


@dataclass(frozen=True)
class VerificationResult:
    allowed: bool
    blocked_reason: str | None = None


class ManifestVerifier:
    """Verifies image manifest signatures and checks Trivy CVE scans against allowlists."""

    @staticmethod
    def verify_signature(
        manifest_digest: str, 
        signature: bytes, 
        public_key_pem: bytes
    ) -> bool:
        """Verify the cosign-compatible ECDSA signature of an image manifest digest."""
        try:
            public_key = load_pem_public_key(public_key_pem)
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                logger.error("Only ECDSA public keys are supported")
                return False

            # Cosign typically signs the raw digest string
            data_to_verify = manifest_digest.encode("utf-8")
            
            public_key.verify(
                signature,
                data_to_verify,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            logger.warning("Invalid cryptographic signature for manifest digest")
            return False
        except Exception as exc:
            logger.error("Signature verification failed with internal error: %s", exc)
            return False

    @staticmethod
    def check_cve_allowlist(
        cve_id: str, 
        cvss_score: float, 
        allowlist_path: str | Path
    ) -> bool:
        """Evaluate if a vulnerability passes the strict gating limits.
        
        ADR: Any CVSS >= 9.0 blocks deployment immediately UNLESS explicitly 
        whitelisted in CVE_allowlist.yaml.
        """
        if cvss_score < _CVSS_CRITICAL_THRESHOLD:
            return True

        path = Path(allowlist_path)
        if not path.is_file():
            logger.warning("Critical CVE %s found, but no CVE_allowlist.yaml provided", cve_id)
            return False

        try:
            with path.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}

            # Support formats:
            # allowed_cves: [{cve_id: "CVE-.."}, ...] 
            # OR simple list of strings: ["CVE-..", ...]
            allowed_list = data.get("allowed_cves", [])
            
            for entry in allowed_list:
                if isinstance(entry, dict) and entry.get("cve_id") == cve_id:
                    logger.info("Critical CVE %s allowed via explicit allowlist", cve_id)
                    return True
                elif isinstance(entry, str) and entry == cve_id:
                    logger.info("Critical CVE %s allowed via explicit allowlist", cve_id)
                    return True

            logger.warning("Critical CVE %s is NOT in the allowlist", cve_id)
            return False
            
        except yaml.YAMLError as exc:
            logger.error("Failed to parse CVE allowlist: %s", exc)
            return False
        except OSError as exc:
            logger.error("Failed to read CVE allowlist: %s", exc)
            return False

    def verify_image(
        self,
        image_ref: str,
        manifest_digest: str,
        signature: bytes,
        public_key_pem: bytes,
        cve_scan_results: list[dict[str, Any]],
        allowlist_path: str | Path
    ) -> VerificationResult:
        """Run the full supply chain verification pipeline on an image."""
        
        logger.info("Starting supply chain verification for %s", image_ref)
        
        # 1. Cryptographic Provenance (Cosign verification equivalent)
        if not self.verify_signature(manifest_digest, signature, public_key_pem):
            return VerificationResult(
                allowed=False,
                blocked_reason="Image manifest signature is invalid or missing"
            )
            
        # 2. CVE Security Gate (Trivy scan results parsing)
        for finding in cve_scan_results:
            cve_id = finding.get("cve_id", "UNKNOWN")
            cvss_score = float(finding.get("cvss_score", 0.0))
            
            if cvss_score >= _CVSS_CRITICAL_THRESHOLD:
                if not self.check_cve_allowlist(cve_id, cvss_score, allowlist_path):
                    return VerificationResult(
                        allowed=False,
                        blocked_reason=f"CRITICAL vulnerability blocked execution: {cve_id} (CVSS {cvss_score})"
                    )

        logger.info("Image %s successfully passed all supply chain barriers", image_ref)
        return VerificationResult(allowed=True)
