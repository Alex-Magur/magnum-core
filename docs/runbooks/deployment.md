# VPS Deployment Guide

## Prerequisites
- VPS with 48 GB RAM minimum (96 GB target)
- Docker & Docker Compose v2+
- Domain with TLS certificate

## Steps
1. Clone repository
2. Configure environment (see deploy/ directory)
3. Generate mTLS certificates: `make certs-dev`
4. Start services: `docker compose up -d`
5. Verify health: `curl https://localhost:8443/health`
