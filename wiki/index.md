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
- [[03-development/development-workflow|Development workflow]]
- [[04-operations/user-guide|User guide]]
- [[05-decisions/adr-0001-rust-gateway|Architecture decisions]]
- [[06-reference/glossary|Glossary]]

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
