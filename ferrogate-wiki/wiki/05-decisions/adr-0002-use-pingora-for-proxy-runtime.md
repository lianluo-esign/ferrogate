---
title: ADR 0002 - Use Pingora for proxy runtime
tags:
  - adr
  - pingora
  - proxy-runtime
  - rust
---

# ADR 0002: Use Pingora for proxy runtime

## Status

Proposed

## Context

FerroGate aims to be a Rust API gateway with AI-native capabilities and a mature gateway operational experience. The project needs a robust proxy foundation for HTTP traffic, upstream routing, load balancing, failover, graceful reload, and observability integration.

The project could build directly on Axum/Hyper, but that would require FerroGate to own many low-level proxy concerns. Cloudflare's Pingora is an open-source Rust framework for building fast, reliable, programmable networked systems and proxies. Pingora is designed around production proxy workloads and includes proxy, load balancing, TLS, and graceful reload building blocks.

## Decision

Use Pingora as FerroGate's primary proxy runtime foundation.

FerroGate should use Pingora for:

- listener and service lifecycle
- HTTP proxy mechanics
- upstream connection handling
- load balancing and failover
- timeouts and retries where appropriate
- graceful reload
- proxy-level observability hooks

FerroGate should own the AI-specific layers:

- OpenAI-compatible API behavior
- model/provider routing
- provider adapters
- policy and quota decisions
- token and usage accounting
- request/response normalization
- admin/config experience

## Consequences

### Positive

- Avoids rebuilding a production proxy runtime from scratch.
- Aligns the gateway with Rust and high-performance networking.
- Gives FerroGate a path to graceful reload and robust upstream behavior.
- Keeps the project focused on AI gateway semantics.
- Provides room for future support of HTTP/2, gRPC, WebSocket, and advanced load balancing.

### Negative

- Pingora has its own abstractions and learning curve.
- Current project prototype may need to move from Axum-first to Pingora-first runtime design.
- Pingora's MSRV and system dependencies may influence FerroGate's build requirements.
- Some AI gateway endpoints such as health/admin APIs may need a clear design for running beside the proxy service.

## Alternatives considered

### Axum/Hyper only

Good for application APIs and initial prototypes, but FerroGate would need to implement more proxy behavior itself.

### Tower stack around Hyper

Flexible and familiar in Rust web services, but still less proxy-specialized than Pingora.

### NGINX/OpenResty/Envoy extension

Mature proxy foundations, but they do not match the Rust-native implementation goal and would reduce FerroGate's control over product experience.

## Follow-up work

- Create a minimal Pingora proxy spike in the main FerroGate codebase.
- Decide how health/admin endpoints are served alongside Pingora.
- Update Rust MSRV and build requirements if Pingora requires newer Rust than the current project.
- Define internal traits between FerroGate request pipeline and Pingora proxy hooks.
