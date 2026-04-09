# Graceful Degradation

ADR Б1.2: 48GB (Min) vs 96GB (Target) configuration.

## 48GB Mode
- SLM Service: DISABLED
- Reranker: DISABLED (fallback to basic Hybrid: Qdrant + SQLite)
- MCP Sampling: Routed to external cloud API with strict content policy
