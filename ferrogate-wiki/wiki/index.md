---
title: FerroGate Wiki
aliases:
  - Home
  - FerroGate Documentation
---

# FerroGate Wiki

Welcome to the FerroGate project wiki. This vault is designed for Obsidian-first writing and Quartz-powered static publishing.

## Start here

- [[00-home/overview|Project overview]]
- [[01-product/product-requirements|Product requirements]]
- [[02-architecture/system-architecture|System architecture]]
- [[02-architecture/ferrogate-architecture-and-modules|Architecture and functional modules]]
- [[02-architecture/mature-api-gateway-design|Mature API gateway design references]]
- [[03-development/development-workflow|Development workflow]]
- [[03-development/prd-implementation-plan|PRD implementation plan]]
- [[04-operations/user-guide|User guide]]
- [[04-operations/self-hosting-runbook|Self-hosting runbook]]
- [[05-decisions/adr-0001-rust-gateway|ADR 0001 - Rust gateway foundation]]
- [[05-decisions/adr-0002-use-pingora-for-proxy-runtime|ADR 0002 - Use Pingora for proxy runtime]]
- [[06-reference/glossary|Glossary]]
- [[06-reference/caddy-source-reference|Caddy source reference]]

## Wiki goals

This wiki captures the complete development process for FerroGate:

1. Product positioning and user scenarios
2. Architecture, design thinking, and key tradeoffs
3. Development workflow, roadmap, and contribution process
4. Operations, deployment, and product usage documentation
5. Architecture Decision Records, references, and glossary

## Publishing

The `wiki/` directory is the source of truth. The `wiki-site/` directory contains the Quartz static site generator. Run:

```bash
./scripts/build-wiki-site.sh
```

The generated site will be written to `wiki-site/public/`.
