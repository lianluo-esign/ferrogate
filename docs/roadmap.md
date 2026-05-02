---
title: Roadmap
description: FerroGate development milestones and implementation progress.
permalink: /roadmap/
---

# FerroGate Roadmap

Last reviewed: 2026-05-03.

The current MVP has completed the gateway core and is moving through provider proxying. Some traffic governance and edge proxy features have already started, but streaming provider forwarding, rate limiting, accounting hooks, fallback policies, automatic HTTPS, and executable hot reload are still open.

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
- Rate limiting
- Token usage accounting hooks
- Provider fallback and routing policies

## Milestone 4: Edge and Caddy-inspired features

- Reverse proxy for generic HTTP services
- Automatic HTTPS support
- Hot config reload
- Docker and Kubernetes deployment examples
