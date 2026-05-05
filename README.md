# FerroGate

**Language:** English | [简体中文](README.zh-CN.md)

FerroGate is an open-source Rust API gateway and AI gateway built on
Cloudflare Pingora. It gives teams a self-hostable control point for LLM
traffic: routing, virtual API keys, provider adapters, policy checks, token
usage accounting, observability, admin APIs, and automatic HTTPS.

The project is developed as the open-source gateway foundation behind
[Token4AI Cloud](https://token4ai.cloud).

## What FerroGate Provides

- **Pingora gateway runtime** for HTTP reverse proxying, route matching,
  upstream pools, path/header rewrites, request IDs, tracing IDs, streaming
  responses, graceful shutdown, and listener-level graceful upgrade.
- **OpenAI-compatible AI API** with `GET /v1/models` and
  `POST /v1/chat/completions`, including non-streaming and streaming SSE
  forwarding.
- **Provider adapters** for OpenAI-compatible APIs, OpenAI, Anthropic, Gemini,
  Grok/xAI, and Azure OpenAI.
- **Model registry and fallback routing** with logical model names, provider
  model mapping, priority fallback, weighted fallback, tenant visibility, and
  provider allow/deny controls.
- **Caddy-style config file compatibility** through `Ferrogate/Caddyfile`
  parsing for familiar reverse-proxy routes, matchers, TLS, logging, and
  gateway settings, alongside structured TOML configuration.
- **Virtual API keys and policy checks** with hashed keys, tenant context,
  scopes, disabled/expired keys, model/provider allowlists and denylists,
  minimal deny-rule policy evaluation, request rate limits, and token budgets.
- **Token usage and billing events** using provider-reported usage when
  available, gateway estimates when needed, and a request reservation /
  settlement flow inspired by production AI gateways.
- **Observability** with structured request logs, billing events, usage
  aggregates, Prometheus metrics, request/trace ID propagation, and OTLP/HTTP
  metrics/logs/traces export.
- **Admin API and dashboard** for gateway status, providers, models, API keys,
  tenants, policies, request logs, billing events, usage aggregates, audit
  events, provider health, config validation, and process-local reload.
- **Automatic HTTPS** with manual TLS, ACME HTTP-01, and ACME DNS-01 through a
  built-in Cloudflare provider. ACME provider credentials are read from the
  configuration file, not environment variables or Python scripts.
- **Supply-chain and security gates** with formatting, clippy, locked metadata,
  high-confidence secret scanning, cargo-deny, cargo-audit, and GitHub Actions.

## Current Status

The planned MVP and production-readiness implementation slice is complete for
the open-source gateway codebase.

Validated end-to-end:

- HTTP reverse proxy runtime on Pingora.
- OpenAI-compatible AI gateway paths.
- Provider adapters and fallback routing.
- Virtual API key auth, policy checks, rate limits, and token budget handling.
- Request logs, billing events, usage aggregates, metrics, and OTLP planning.
- Admin API, static dashboard, config validation, and process-local reload.
- Manual TLS, ACME HTTP-01, and ACME DNS-01.
- Real Let's Encrypt staging and production issuance for both HTTP-01 and
  Cloudflare DNS-01 during live validation.

Still intentionally scoped as next-stage production work:

- Persistent storage implementations for API keys, tenants, policy, billing,
  request logs, and audit logs. Current runtime state is primarily config and
  in-memory repository driven.
- Full Admin API CRUD control plane.
- Background ACME renewal and hot certificate reload. Current ACME behavior is
  startup-time issuance/reuse.
- Expanded DNS provider set beyond the built-in Cloudflare provider and the
  generic external hook boundary.

## Repository Layout

```text
crates/
  ferrogate-cli             CLI, Pingora runtime wiring, gateway handlers
  ferrogate-config          Caddyfile/TOML config model and parser
  ferrogate-providers       AI provider adapters and model registry
  ferrogate-auth            Tenant and RBAC domain models
  ferrogate-policy          Policy decision models and engine
  ferrogate-storage         Repository traits and in-memory storage
  ferrogate-billing         Token usage, cost, and billing event models
  ferrogate-observability   Metrics, spans, exporter contracts
  ferrogate-runtime         Reload and runtime lifecycle state machine
config/                     Example TOML configuration
Ferrogate/Caddyfile          Default Caddyfile-style development config
scripts/security-check.sh    Local security and supply-chain gate
```

## Quick Start

Prerequisites:

- Rust toolchain compatible with the workspace `rust-version`.
- `cmake`, `g++`, `make`, and `pkg-config` for Pingora's native compression
  dependency chain.

Run the default development gateway:

```bash
cargo run -- run --config Ferrogate/Caddyfile
```

Validate configuration:

```bash
cargo run -- validate --config Ferrogate/Caddyfile
cargo run -- validate --config config/ferrogate.example.toml
```

Probe the gateway:

```bash
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/proxy/httpbin/get
curl -H 'Authorization: Bearer dev-secret' http://127.0.0.1:8080/v1/models
```

Send an OpenAI-compatible chat request:

```bash
curl -X POST http://127.0.0.1:8080/v1/chat/completions \
  -H 'Authorization: Bearer dev-secret' \
  -H 'Content-Type: application/json' \
  -d '{"model":"fast-chat","messages":[{"role":"user","content":"hello"}]}'
```

Open the admin dashboard:

```text
http://127.0.0.1:8080/admin
```

## Configuration

FerroGate loads `Ferrogate/Caddyfile` by default. TOML is also supported for
structured self-hosting and tests.

```bash
ferrogate run --config Ferrogate/Caddyfile
ferrogate run --config /etc/ferrogate/ferrogate.toml
```

### Caddyfile Example

```caddyfile
:8080 {
    log

    respond /healthz "ok" 200

    ai_gateway {
        provider openai {
            kind openai-compatible
            base_url https://api.openai.com/v1
            api_key {env.OPENAI_API_KEY}
        }

        model fast-chat -> openai:gpt-4o-mini {
            capabilities chat streaming
            input_price_per_1m 0.15
            output_price_per_1m 0.60
        }

        api_key key_dev {
            key {$FERROGATE_DEV_KEY}
            scopes models.read chat.completions admin.read
            allowed_models fast-chat
            allowed_providers openai
            request_limit_per_minute 60
            monthly_token_budget 1000000
        }
    }

    route /v1/* {
        reverse_proxy https://api.openai.com {
            header_up Authorization "Bearer {env.OPENAI_API_KEY}"
        }
    }
}
```

### TOML Example

```toml
listen = "0.0.0.0:8080"

[admin]
listen = "127.0.0.1:2019"

[reliability]
provider_circuit_breaker_failure_threshold = 3
provider_circuit_breaker_cooldown_secs = 30
provider_dispatch_timeout_secs = 10
provider_dispatch_max_retries = 1
graceful_shutdown_grace_period_secs = 3
graceful_shutdown_timeout_secs = 15

[[providers]]
name = "openai"
kind = "openai-compatible"
base_url = "https://api.openai.com/v1"
api_key_env = "OPENAI_API_KEY"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat", "streaming"]
input_price_per_1m = "0.15"
output_price_per_1m = "0.60"

[[api_keys]]
id = "dev"
key = "dev-secret"
scopes = ["models.read", "chat.completions", "admin.read"]
allowed_models = ["fast-chat"]
allowed_providers = ["openai"]
request_limit_per_minute = 60
monthly_token_budget = 1000000
```

For production, prefer `key_hash` generated by `ferrogate hash-key` over plain
development keys.

```bash
ferrogate hash-key --secret 'your-client-secret'
```

## Automatic HTTPS

FerroGate supports manual TLS certificates and startup-time ACME issuance.

### Manual TLS

```toml
[tls]
enabled = true
cert_path = "/etc/ferrogate/certs/fullchain.pem"
key_path = "/etc/ferrogate/certs/privkey.pem"
http2 = true
```

### ACME HTTP-01

HTTP-01 requires public inbound access to port 80 for the challenge and port
443 for HTTPS service.

```toml
listen = "0.0.0.0:443"

[tls]
enabled = true
http2 = true

[tls.acme]
enabled = true
domains = ["api.example.com"]
email = "ops@example.com"
directory_url = "https://acme-v02.api.letsencrypt.org/directory"
terms_agreed = true
challenge = "http-01"
http_challenge_listen = "0.0.0.0:80"
storage_dir = "/var/lib/ferrogate/acme-http"
```

### ACME DNS-01 With Built-In Cloudflare

DNS-01 does not require public port 80 and is required for wildcard
certificates. Cloudflare credentials are configured in the FerroGate config
file.

```toml
listen = "0.0.0.0:443"

[tls]
enabled = true
http2 = true

[tls.acme]
enabled = true
domains = ["api.example.com"]
email = "ops@example.com"
directory_url = "https://acme-v02.api.letsencrypt.org/directory"
terms_agreed = true
challenge = "dns-01"
storage_dir = "/var/lib/ferrogate/acme-dns"
dns_provider = "cloudflare"
dns_config = { api_token = "cf-token", zone_name = "example.com" }
dns_propagation_delay_secs = 30
```

Caddyfile-style DNS-01:

```caddyfile
api.example.com {
    tls {
        issuer acme {
            email ops@example.com
        }
        storage /var/lib/ferrogate/acme-dns
        dns cloudflare {
            api_token cf-token
            zone_name example.com
        }
    }
}
```

FerroGate also keeps a provider-neutral external hook boundary for DNS
providers that are not built in. Hooks receive a 0600 JSON payload file path and
are invoked as:

```text
<hook> <set|cleanup> <payload-json-path>
```

## Reloading

Validate-only reload report:

```bash
ferrogate reload --config Ferrogate/Caddyfile
```

Process-local reload through a running Admin API:

```bash
ferrogate reload \
  --config Ferrogate/Caddyfile \
  --admin-url http://127.0.0.1:8080 \
  --admin-token "$FERROGATE_ADMIN_TOKEN"
```

Listener-level reload through Pingora graceful upgrade:

```bash
ferrogate reload --config Ferrogate/Caddyfile --graceful-upgrade
```

Process-local reload is used only when the listen socket and TLS listener
fingerprint do not change. Listener/TLS changes require graceful upgrade.

## Admin API

Common endpoints:

```text
GET  /admin/v1/status
GET  /admin/v1/providers
GET  /admin/v1/provider-health
GET  /admin/v1/models
GET  /admin/v1/api-keys
GET  /admin/v1/tenants
GET  /admin/v1/policies
GET  /admin/v1/request-logs
GET  /admin/v1/billing-events
GET  /admin/v1/usage-aggregates
GET  /admin/v1/audit-events
POST /admin/v1/config/validate
POST /admin/v1/config/reload
GET  /metrics
GET  /admin
```

Read endpoints require `admin.read` when API keys are configured. Config
validation and reload require `admin.write`.

## Docker

Stable releases use date-based tags such as `v2026.05.05`.

Pull the published GitHub Packages image and run it with a mounted config:

```bash
docker pull ghcr.io/lianluo-esign/ferrogate:v2026.05.05

docker run --rm \
  -p 8080:8080 \
  -v "$PWD/config/ferrogate.example.toml:/etc/ferrogate/ferrogate.toml:ro" \
  -e FERROGATE_CONFIG=/etc/ferrogate/ferrogate.toml \
  ghcr.io/lianluo-esign/ferrogate:v2026.05.05
```

Build a local image when developing Docker changes:

```bash
docker build -t ferrogate .
```

For automatic HTTPS, publish the relevant ports and mount ACME storage:

```bash
docker run --rm \
  -p 80:80 \
  -p 443:443 \
  -v /etc/ferrogate/ferrogate.toml:/etc/ferrogate/ferrogate.toml:ro \
  -v /var/lib/ferrogate/acme:/var/lib/ferrogate/acme \
  -e FERROGATE_CONFIG=/etc/ferrogate/ferrogate.toml \
  ghcr.io/lianluo-esign/ferrogate:v2026.05.05
```

## Quality And Security

Run the local gate before committing:

```bash
./scripts/security-check.sh
```

Strict mode requires cargo-deny and cargo-audit:

```bash
FERROGATE_SECURITY_REQUIRE_TOOLS=1 ./scripts/security-check.sh
```

Install the supply-chain tools:

```bash
cargo install cargo-deny --version 0.19.4 --locked
cargo install cargo-audit --version 0.22.1 --locked
```

The security gate runs:

- `cargo fmt --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo metadata --locked`
- high-confidence secret scanning
- `cargo deny check licenses bans sources`
- `cargo audit`

Known residual audit warnings are documented in `.cargo/audit.toml` and the
development plan. They currently come from Pingora transitive dependencies and
are monitored separately from direct FerroGate code.

## Documentation

- Project roadmap: [`docs/roadmap.md`](docs/roadmap.md)
- Performance testing guide:
  [`docs/performance-testing.md`](docs/performance-testing.md)
- Example TOML configuration:
  [`config/ferrogate.example.toml`](config/ferrogate.example.toml)
- Default Caddyfile-style configuration:
  [`Ferrogate/Caddyfile`](Ferrogate/Caddyfile)

Internal development planning notes are maintained outside this product
repository.

## Contributing

1. Keep changes small and reviewable.
2. Follow the existing Rust module boundaries and Caddyfile adapter style.
3. Run `./scripts/security-check.sh` before opening a PR.
4. Update public product documentation when behavior, configuration,
   operations, or architecture changes.
5. Do not commit provider secrets, ACME tokens, private keys, or generated
   certificates.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
