---
title: Project overview
---

# Project overview

FerroGate is an open-source Rust gateway for AI traffic. It provides a reverse-proxy foundation for routing, securing, observing, and governing requests to LLM providers.

## Mission

Make AI API traffic easier to operate in production by providing a small, transparent, and extensible gateway layer.

## Core principles

- Rust-native reliability and performance
- OpenAI-compatible developer experience
- Configuration-first operations
- Self-hosting runbook for binary, Docker, TLS, health checks, shutdown windows, and capacity planning
- Provider-neutral routing
- Clear observability and governance hooks
- Open-source friendly documentation and contribution workflow

## Current milestone

The first milestone is a minimal gateway core:

- Health check endpoint
- OpenAI-compatible model listing placeholder
- TOML configuration loading
- CLI commands for serving and validating config
