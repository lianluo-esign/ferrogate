---
title: Mature API gateway design references
tags:
  - api-gateway
  - product-design
  - configuration
---

# Mature API gateway design references

FerroGate should borrow proven ideas from mature API gateway products, but implement the system in Rust and specialize it for AI traffic.

The goal is not to copy one product's implementation. The goal is to reproduce the important API gateway capabilities that production users expect, then extend them with AI-native capabilities.

## Gateway capabilities FerroGate should reproduce

- reverse proxy
- route matching
- upstream selection
- TLS listener support
- config-driven operation
- hot/graceful reload
- middleware pipeline
- authentication and authorization
- rate limiting and quota control
- structured access logs
- metrics and tracing hooks
- admin/control API
- built-in module boundaries

## FerroGate-specific extension

FerroGate extends the generic API gateway model with:

- virtual API keys
- AI provider adapters
- model registry and aliases
- OpenAI-compatible facade
- token metering
- AI cost calculation
- tenant-aware governance
- OpenTelemetry tracing across AI request stages
- AI request dashboard

## Configuration design

FerroGate's primary startup configuration must be compatible with Caddyfile-style configuration. The standard supported startup path is `Ferrogate/Caddyfile`.

TOML can still be used as an internal typed schema, test fixture format, or transitional debug format, but it must not replace the Caddyfile compatibility goal.

The Caddyfile-compatible implementation should be designed by reading Caddy's official source code as a product semantics reference, especially its Caddyfile parser, HTTP Caddyfile adapter, directive ordering, route handling, `reverse_proxy`, `tls`, and `log` behavior. FerroGate must reimplement the compatible semantics in Rust with Pingora and its own module boundaries, not copy Caddy's Go source code or internal architecture.

Example FerroGate Caddyfile direction:

```text
:8080 {
  ai_gateway {
    route /v1/chat/completions {
      model fast-chat -> openai:gpt-4o-mini
      model best-reasoning -> anthropic:claude-3-5-sonnet
    }

    provider openai {
      base_url https://api.openai.com/v1
      api_key {env.OPENAI_API_KEY}
    }

    policy default {
      require_key true
      max_tokens_per_request 32000
      rate_limit 60r/m
    }
  }
}
```

This syntax is a first-class product direction. The implementation should first support a practical Caddyfile subset for reverse proxy, routing, headers, rewrite, logs, TLS, and static responses, then extend it with AI Gateway directives after the internal runtime model is stable.

Current implemented `ai_gateway` subset:

- `provider <name> { kind ... base_url ... api_key env.NAME/{env.NAME}/{$NAME} }`
- `model <logical-name> -> <provider>:<provider-model> { capabilities ... context_window ... input_price_per_1m ... output_price_per_1m ... }`
- `api_key <id> { key env.NAME/{env.NAME}/{$NAME} scopes ... allowed_models ... denied_models ... allowed_providers ... denied_providers ... monthly_token_budget ... request_limit_per_minute ... }`

The parser maps this subset to the same typed config model used by TOML, so validation, auth, routing, token budgeting, billing, and provider dispatch do not need a separate Caddyfile-specific runtime path.

## Caddy Source Comparison Notes

Reference tree: `.references/caddy` (local Caddy source snapshot recorded during P0).

Observed Caddy semantics relevant to FerroGate:

- `caddyconfig/caddyfile.Parse` first tokenizes and groups input into server blocks and segments. It expands `{$ENV}` before parsing, while `{env.NAME}` remains a runtime placeholder token in HTTP handlers.
- `caddyconfig/caddyfile.Dispenser` treats `{` as a block opener, not a line argument. FerroGate mirrors this for normal braces and only treats `{env.NAME}` / `{$NAME}` as argument tokens for Secret references because the current typed config needs to preserve env indirection instead of eagerly substituting secrets.
- `caddyconfig/httpcaddyfile.RegisterHandlerDirective` extracts an optional matcher token before building HTTP routes. FerroGate currently supports the same broad shape for simple path matchers and named matcher declarations, but maps directly into `RouteRule` instead of Caddy module JSON.
- Caddy sorts HTTP directives by `defaultDirectiveOrder`, then sub-sorts common path matchers by specificity. FerroGate's current adapter preserves source order for the supported subset except where nested `route`/`handle`/`handle_path` scopes collapse into a typed route; this is acceptable for the MVP subset because unsupported directives fail fast rather than silently reordering mixed middleware.
- Caddy `route` parses child directives as a subroute without applying the normal directive-order sort, while `handle` builds mutually exclusive grouped subroutes. FerroGate currently treats `route`, `handle`, and `handle_path` as structural path-scope helpers for one proxy/static route, not as a full middleware graph.
- Caddy `handle_path` requires a slash-prefixed path matcher and prepends a rewrite that strips the matched prefix. FerroGate's `handle_path` maps this to `RouteRule.path_prefixes` plus `strip_prefix` semantics.
- Caddy `reverse_proxy` accepts multiple upstreams and many subdirectives. FerroGate's implemented subset covers positional upstreams plus `header_up`/`header_down`; advanced load balancing, active/passive health checks, transports, and response interception remain explicit future work.

Design consequence: FerroGate should keep using a narrow, typed Caddyfile adapter with source-span diagnostics until the internal runtime can represent a richer middleware graph. New Caddyfile directives should be added only when they can either map unambiguously to existing typed config or be rejected with a clear migration hint.

## Built-in module architecture

Potential module categories:

- provider adapters
- auth methods
- policy checks
- observability sinks
- token counters
- config loaders
- admin APIs
- dashboard feature modules

## What to avoid

- Do not copy another gateway's source architecture directly.
- Do not introduce external plugin complexity. Provider, policy, observability, and dashboard capabilities should be built in first.
- Do not prioritize cosmetic syntax over runtime correctness, but Caddyfile compatibility is a product requirement and must be implemented through a typed internal config model.
- Do not make the AI proxy a thin add-on. AI capabilities must be first-class.

## Success criteria

FerroGate succeeds when:

- it can operate as a real API gateway
- it can route and govern AI traffic across providers
- it can be configured quickly and safely
- it has a clear admin API and dashboard path
- it provides full traceability, usage accounting, and enterprise isolation
