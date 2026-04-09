# 🚀 Forge Core Ultra v12.0 — Diamond Citadel (DC)

**MCP-Native, A2A & Zero-Trust LLM Code-Agent Platform**

## Architecture

Single-node hardened deployment on VPS (48 GB Min / 96 GB Target).

- **MCP-First** with OAuth 2.1, Constrained Decoding, Secure Sampling
- **Zero-Trust** with strict mTLS (SPIFFE/SPIRE), Landlock, OPA
- **Durable Graph** — LangGraph with transactional idempotency
- **Hybrid Retrieval** — Qdrant + SQLite FTS5 + Cross-Encoder Reranker
- **Observability** — OpenTelemetry end-to-end tracing

## Project Structure

```
services/         → Microservices (forge_api, graph_worker, mcp_gateway, jcodemunch, sandbox)
libs/             → Shared libraries (security, retrieval, storage, telemetry, a2a)
deploy/           → Infrastructure configs (Docker, mTLS, OTel, Prometheus, Jaeger)
policies/         → Policy-as-Code (OPA, OpenShell, tool manifests)
slm/              → SLM Service config (llama.cpp, grammars)
storage/          → Runtime data directories (git-ignored)
tests/            → Phase Gate acceptance tests (phase0–phase5)
evals/            → Evaluation suites and datasets
docs/             → Architecture docs, runbooks, ADR history
scripts/          → Dev and CI/CD helper scripts
```

## Quick Start

```bash
make setup        # Install dependencies
make dev          # Start development environment
make test         # Run all tests
make phase-gate   # Run Phase Gate evals
```

## Tech Stack

- **Language:** Python 3.12+
- **API Framework:** FastAPI
- **Graph Engine:** LangGraph
- **Storage:** SQLite >= 3.45.0 (JSONB), Qdrant
- **SLM:** llama.cpp
- **Security:** SPIFFE/SPIRE, OPA, Landlock, cosign/Trivy
- **Observability:** OpenTelemetry, Prometheus, Jaeger

## ADR

See [ADR.md](../ADR.md) — the Absolute Contract (Source of Truth) for this project.

## License

Proprietary. All rights reserved.
