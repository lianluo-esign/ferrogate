---
title: ADR 0001 - Rust gateway foundation
---

# ADR 0001: Rust gateway foundation

## Status

Accepted

## Context

FerroGate needs to be reliable, efficient, and suitable for long-running production workloads that proxy AI traffic.

## Decision

Use Rust as the implementation language and Axum/Tokio as the initial async HTTP foundation.

## Consequences

- Strong performance and memory safety properties.
- Good async ecosystem for HTTP workloads.
- Slightly higher contribution barrier than dynamic languages.
- Clear type boundaries can help provider integrations remain maintainable.
