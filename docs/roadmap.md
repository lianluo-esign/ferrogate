---
title: Roadmap
description: FerroGate development milestones and implementation progress.
permalink: /roadmap/
---

# FerroGate Roadmap

Last reviewed: 2026-05-06.

The current MVP has completed the gateway core, provider proxying, admin read/write audit surfaces, the P6 observability/accounting slice, and the P8 production hardening slice. P9 performance stability hardening is now in progress. Production reliability now includes configurable provider circuit breakers, provider dispatch timeout/retry controls, bounded non-streaming provider response bodies, admin provider health checks, API key request limits, token-budget reservation/settlement, bounded in-memory request/audit/billing retention, paginated Admin event/log reads, write-time Prometheus metric accumulation, precompiled reverse-proxy runtime routes/upstream endpoints/header mutations, rate-limited error access logs, manual TLS listener support, ACME DNS-01 startup certificate provisioning, process-local admin config reload, Pingora graceful-upgrade listener handoff, graceful shutdown windows, AI streaming perf smoke coverage, a local and CI security-check gate, and a self-hosting runbook. Durable storage remains open.

## Milestone 1: Gateway core

- HTTP server lifecycle
- Configuration loading and validation
- Health checks
- OpenAI-compatible route skeleton

## Milestone 2: AI provider proxying

- OpenAI-compatible chat completions proxy
- Provider credentials from environment variables
- Streaming response support
- Request and response tracing

## Milestone 3: Traffic governance

- API key authentication
- API key request limiting and token-budget reservation/settlement
- Token usage accounting hooks and OTLP/Prometheus observability
- Provider fallback, retry, circuit breaking, and routing policies
- Admin provider health checks and dashboard health view
- Manual TLS listener with certificate/key validation and optional HTTP/2 ALPN
- ACME automatic HTTPS startup provisioning through DNS-01 hooks
- Graceful shutdown window configuration for Pingora SIGTERM handling
- AI streaming concurrent dispatch perf smoke with RSS and p95 bounds
- Local and CI supply-chain/security gate with secret scan, cargo-deny, and cargo-audit policy
- Self-hosting runbook for binary, Docker, systemd, capacity planning, and incidents

## Milestone 4: Edge and Caddy-inspired features

- Reverse proxy for generic HTTP services
- Automatic HTTPS support
- Automatic listener/TLS-level config reload orchestration beyond the current explicit graceful-upgrade command
- Docker and Kubernetes deployment examples
