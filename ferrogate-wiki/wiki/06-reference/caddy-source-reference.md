---
title: Caddy source reference
aliases:
  - Caddy 源码对照
  - Caddy Source Reference
tags:
  - reference
  - caddy
  - configuration
  - api-gateway
---

# Caddy source reference

FerroGate uses Caddy's official source code as a product semantics reference for Caddyfile-compatible configuration and mature reverse-proxy behavior.

## Local reference checkout

- Local path: `.references/caddy`
- Upstream: <https://github.com/caddyserver/caddy>
- Reference commit: `18ab0f955fc1075d7727c7658dbfb734c673a5c9`
- Tracking policy: `.references/` is ignored by git and must not be committed into FerroGate.

## Clean-room rule

Caddy source code is for semantic comparison and design review only.

FerroGate must:

- understand Caddy's product behavior, Caddyfile grammar, directive semantics, ordering, routing model, logging, TLS and reverse proxy behavior;
- reimplement compatible behavior in Rust with Pingora and FerroGate's own module boundaries;
- avoid copying Caddy's Go source code, internal package structure, or implementation details;
- document any compatibility difference with clear migration guidance.

## Key Caddy source areas to compare

| Caddy area | Local source path | FerroGate implementation concern |
| --- | --- | --- |
| Caddyfile lexer/parser | `.references/caddy/caddyconfig/caddyfile/` | `Ferrogate/Caddyfile` tokenization, block parsing, import behavior, error diagnostics |
| HTTP Caddyfile adapter | `.references/caddy/caddyconfig/httpcaddyfile/` | Site block adaptation, directive sorting, matcher parsing, route assembly |
| Caddyfile integration fixtures | `.references/caddy/caddytest/integration/caddyfile_adapt/` | Compatibility test cases and unsupported directive diagnostics |
| HTTP app modules | `.references/caddy/modules/caddyhttp/` | Handler chain, route/matcher semantics, logging, TLS-related HTTP behavior |
| Reverse proxy | `.references/caddy/modules/caddyhttp/reverseproxy/` | Upstream model, load balancing, health checks, retries, streaming semantics |

## Initial compatibility checklist

- [ ] Global options block.
- [ ] Site block addresses such as `:8080`, `localhost:8080`, `example.com`.
- [ ] Matchers for path, host, method, header and query.
- [ ] `reverse_proxy` with one or multiple upstreams.
- [ ] `route`, `handle`, `handle_path` ordering and grouping.
- [ ] `header` request/response operations.
- [ ] `rewrite` / `uri` path rewriting.
- [ ] `respond` static responses.
- [ ] `redir` redirects.
- [ ] `encode` compression declaration.
- [ ] `tls` manual certificate configuration.
- [ ] `log` access log configuration.
- [ ] Clear error diagnostics for unsupported Caddy directives.
