#!/usr/bin/env bash
# Phase Gate Runner
# ADR Б0.9 & Б16: Run acceptance criteria tests per phase
set -euo pipefail

PHASE="${1:-all}"

echo "🚦 Running Phase Gate: $PHASE"

if [ "$PHASE" = "all" ]; then
    uv run pytest tests/ -v --tb=short
else
    uv run pytest "tests/phase${PHASE}/" -v --tb=short -m "phase${PHASE}"
fi
