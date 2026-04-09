# Security Model

ADR Б2: Zero-Trust architecture overview.

## Layers
1. OAuth 2.1 Resource Server (Б2.1)
2. Tool Manifest Signing & CVE-Gate (Б2.2)
3. Tiered Risk Engine — ONNX Classifier (Б2.3)
4. Key Management & Crypto Operations (Б2.4)
5. Kernel-Level Isolation — Landlock/OPA (Б0.3)
6. Strict mTLS — SPIFFE/SPIRE (Б1.1)
