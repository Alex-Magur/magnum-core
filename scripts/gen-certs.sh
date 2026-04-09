#!/usr/bin/env bash
# Generate development mTLS certificates
# ADR Б1.1: strict mTLS (SPIFFE/SPIRE)
set -euo pipefail

echo "🔐 Generating development mTLS certificates..."
echo "⚠️  These are for DEVELOPMENT ONLY. Production uses SPIRE."

CERT_DIR="$(dirname "$0")/../deploy/mtls/dev-certs"
mkdir -p "$CERT_DIR"

# Generate CA
openssl req -x509 -newkey rsa:4096 -days 365 -nodes \
    -keyout "$CERT_DIR/ca.key" -out "$CERT_DIR/ca.crt" \
    -subj "/CN=Forge Dev CA"

echo "✅ Development certificates generated in $CERT_DIR"
