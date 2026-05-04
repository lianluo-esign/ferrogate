---
title: Self-hosting runbook
---

# Self-hosting runbook

This runbook describes the current FerroGate self-hosting path for P8. It covers a single-node deployment, manual or ACME-provisioned TLS certificates, provider secrets, health checks, graceful shutdown, and capacity sizing.

## Deployment shape

Use one of these entrypoints:

- Binary: build `target/release/ferrogate` and run it under systemd or another process supervisor.
- Docker: build the image locally and mount a config file plus optional certificate directory.
- Local validation: run `ferrogate validate --config <path>` before replacing a running process.

FerroGate currently stores request logs, billing events, usage aggregates, token reservations, request windows, and provider circuit state in memory. Restarting the process clears those in-memory runtime records. Durable storage remains a later deployment slice.

## Minimal production TOML

```toml
listen = "0.0.0.0:8443"

[tls]
enabled = true
cert_path = "./certs/fullchain.pem"
key_path = "./certs/privkey.pem"
http2 = true

[telemetry]
service_name = "ferrogate-prod"
log_bodies = false
otlp_endpoint = "http://127.0.0.1:4318"

[reliability]
provider_circuit_breaker_failure_threshold = 3
provider_circuit_breaker_cooldown_secs = 30
provider_dispatch_timeout_secs = 10
provider_dispatch_max_retries = 1
graceful_shutdown_grace_period_secs = 3
graceful_shutdown_timeout_secs = 15

[[providers]]
name = "openai"
kind = "openai"
base_url = "https://api.openai.com/v1"
api_key_env = "OPENAI_API_KEY"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat", "streaming"]
input_price_per_1m = 0.15
output_price_per_1m = 0.60

[[api_keys]]
id = "key_prod_admin"
name = "Production admin"
key_env = "FERROGATE_ADMIN_KEY"
scopes = ["models.read", "chat.completions", "admin.read", "admin.write"]
allowed_models = ["fast-chat"]
denied_models = []
allowed_providers = ["openai"]
denied_providers = []
monthly_token_budget = 10000000
request_limit_per_minute = 120

[[api_keys]]
id = "key_prod_app"
name = "Production app"
key_env = "FERROGATE_APP_KEY"
scopes = ["models.read", "chat.completions"]
allowed_models = ["fast-chat"]
denied_models = []
allowed_providers = ["openai"]
denied_providers = []
monthly_token_budget = 5000000
request_limit_per_minute = 60
```

Relative TLS paths are resolved from the config file directory. Keep provider keys and client API keys in environment variables; avoid inline `key` outside development.

## Automatic HTTPS with DNS-01

FerroGate can request a Let's Encrypt-compatible certificate at startup through ACME DNS-01. Use this mode instead of `tls.cert_path` and `tls.key_path`.

```toml
listen = "0.0.0.0:8443"

[tls]
enabled = true
http2 = true

[tls.acme]
enabled = true
domains = ["api.example.com"]
email = "ops@example.com"
directory_url = "https://acme-v02.api.letsencrypt.org/directory"
terms_agreed = true
storage_dir = "./acme"
dns_provider = "cloudflare"
dns_config = { api_token = "cf-token", zone_id = "zone-123" }
dns_propagation_delay_secs = 30
```

Caddyfile-style configuration is also supported:

```caddyfile
api.example.com {
    tls {
        issuer acme {
            email ops@example.com
        }
        storage ./acme
        dns cloudflare {
            provider cloudflare
            api_token cf-token
            zone_id zone-123
        }
    }
}
```

The DNS automation boundary is provider-neutral and configuration-driven. Built-in Cloudflare DNS-01 uses `dns_provider = "cloudflare"` and `dns_config` with `api_token` plus either `zone_id` or `zone_name`; it does not rely on provider environment variables or Python/script runtimes. For custom DNS providers, configure `dns_hook_set` and `dns_hook_cleanup`; FerroGate writes a 0600 JSON payload under `tls.acme.storage_dir` and invokes hooks as `<hook> <action> <payload-json-path>`.

Startup behavior:

1. FerroGate reuses `storage_dir/certificates/.../fullchain.pem` and `privkey.pem` when both files are readable and valid.
2. If no usable cached certificate exists, FerroGate creates or restores the ACME account under `storage_dir/accounts/`.
3. FerroGate runs the DNS set hook for each authorization, waits `dns_propagation_delay_secs`, marks challenges ready, downloads the certificate, writes `fullchain.pem` plus `privkey.pem`, and starts the Pingora TLS listener.
4. DNS cleanup is best-effort after challenge validation.

Current limitation: renewal is startup-driven. Restart the service before certificate expiry, or schedule a controlled graceful upgrade/restart as part of certificate lifecycle automation. Runtime hot certificate reload without listener restart remains a later listener-management task.

HTTP-01 is available for non-wildcard domains when port 80 can reach FerroGate:

```toml
[tls.acme]
enabled = true
domains = ["api.example.com"]
email = "ops@example.com"
directory_url = "https://acme-v02.api.letsencrypt.org/directory"
terms_agreed = true
challenge = "http-01"
http_challenge_listen = "0.0.0.0:80"
storage_dir = "./acme"
```

For Docker deployments, publish both `80:80` and the HTTPS listener port, for example `443:443`.

## Preflight

Run these checks before rollout:

```bash
cargo build --release
./target/release/ferrogate validate --config ./config/production.toml
cargo install cargo-deny --version 0.19.4 --locked
cargo install cargo-audit --version 0.22.1 --locked
FERROGATE_SECURITY_REQUIRE_TOOLS=1 ./scripts/security-check.sh
```

The security script always runs formatting, clippy, locked dependency metadata validation, and high-confidence secret scanning. With `FERROGATE_SECURITY_REQUIRE_TOOLS=1`, missing `cargo deny` or `cargo audit` fails the gate. `cargo deny` uses `deny.toml` for license, duplicate dependency, and source policy. `cargo audit` uses `.cargo/audit.toml`; it currently records a temporary `RUSTSEC-2024-0437` ignore for the Pingora metrics dependency chain (`pingora-core 0.8 -> prometheus 0.13 -> protobuf 2.x`) until upstream can move off protobuf 2.x.

## Binary deployment

```bash
install -m 0755 target/release/ferrogate /usr/local/bin/ferrogate
install -d -m 0750 /etc/ferrogate /etc/ferrogate/certs
install -m 0640 config/production.toml /etc/ferrogate/ferrogate.toml
install -m 0640 certs/fullchain.pem /etc/ferrogate/certs/fullchain.pem
install -m 0600 certs/privkey.pem /etc/ferrogate/certs/privkey.pem
```

Example systemd unit:

```ini
[Unit]
Description=FerroGate AI gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=OPENAI_API_KEY=replace-me
Environment=FERROGATE_ADMIN_KEY=replace-me
Environment=FERROGATE_APP_KEY=replace-me
ExecStart=/usr/local/bin/ferrogate run --config /etc/ferrogate/ferrogate.toml
ExecReload=/usr/local/bin/ferrogate validate --config /etc/ferrogate/ferrogate.toml
Restart=on-failure
RestartSec=2
KillSignal=SIGTERM
TimeoutStopSec=25
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=/etc/ferrogate

[Install]
WantedBy=multi-user.target
```

Set `TimeoutStopSec` greater than `graceful_shutdown_grace_period_secs + graceful_shutdown_timeout_secs`. Pingora treats `SIGTERM` as graceful termination and `SIGINT` as fast shutdown.

## Docker deployment

```bash
docker build -t ferrogate:local .
docker run --rm \
  -p 8443:8443 \
  -e OPENAI_API_KEY \
  -e FERROGATE_ADMIN_KEY \
  -e FERROGATE_APP_KEY \
  -v "$PWD/config/production.toml:/etc/ferrogate/ferrogate.toml:ro" \
  -v "$PWD/certs:/etc/ferrogate/certs:ro" \
  ferrogate:local \
  run --config /etc/ferrogate/ferrogate.toml
```

Validate the mounted config inside the same image before rollout:

```bash
docker run --rm \
  -e OPENAI_API_KEY \
  -e FERROGATE_ADMIN_KEY \
  -e FERROGATE_APP_KEY \
  -v "$PWD/config/production.toml:/etc/ferrogate/ferrogate.toml:ro" \
  -v "$PWD/certs:/etc/ferrogate/certs:ro" \
  ferrogate:local \
  validate --config /etc/ferrogate/ferrogate.toml
```

## Health and operations checks

Use these checks after startup:

```bash
curl -k https://127.0.0.1:8443/healthz
curl -k -H "Authorization: Bearer $FERROGATE_ADMIN_KEY" https://127.0.0.1:8443/admin/v1/status
curl -k -H "Authorization: Bearer $FERROGATE_ADMIN_KEY" https://127.0.0.1:8443/admin/v1/provider-health
curl -k -H "Authorization: Bearer $FERROGATE_ADMIN_KEY" https://127.0.0.1:8443/metrics
```

Operational signals to watch:

- `provider-health`: `status`, `reachable`, `circuit_open`, and `consecutive_failures`.
- `request-logs`: status code, route/model/provider, request id, trace id, and error code.
- `usage-aggregates`: token usage by API key/model/provider.
- `billing-events`: `usage_source` should normally be `provider_usage`; `gateway_estimate` indicates missing provider usage or streaming estimate fallback.
- `/metrics`: request totals, token totals, cost totals, and model/provider labels.

## Capacity planning

Start conservative, then measure with local perf smoke and real provider latency:

| Workload | Starting point |
| --- | --- |
| Low traffic dev or internal tools | 1 vCPU, 512 MB RAM |
| Small production API gateway | 2 vCPU, 1 GB RAM |
| Streaming-heavy or high fan-out traffic | 4 vCPU, 2 GB RAM, then scale horizontally |

Sizing rules:

- CPU grows with concurrent request parsing, JSON validation, TLS handshakes, and streaming fan-out.
- Memory grows with active connections, streaming buffers, in-memory request logs, billing events, usage aggregates, token reservations, and circuit state.
- Keep request body logging disabled in production unless debugging a scoped incident.
- Keep `provider_dispatch_timeout_secs` below the client timeout so clients receive FerroGate errors instead of hanging.
- Set `provider_dispatch_max_retries` low for streaming-heavy traffic; retrying before first bytes is useful, but repeated retries can amplify provider load.
- Use per-key `request_limit_per_minute` and `monthly_token_budget` to isolate tenants and cap blast radius.

## Rollout procedure

1. Build or pull the new binary/image.
2. Validate config and TLS material with `ferrogate validate`.
3. Run `FERROGATE_SECURITY_REQUIRE_TOOLS=1 ./scripts/security-check.sh`.
4. Start one instance and check `/healthz`, `/admin/v1/status`, `/admin/v1/provider-health`, and `/metrics`.
5. Send a small `/v1/models` and `/v1/chat/completions` request with a non-admin API key.
6. Watch request logs, usage aggregates, and provider health for at least one provider dispatch cycle.
7. Shift traffic gradually.

## Incident runbook

Provider outage:

1. Check `/admin/v1/provider-health`.
2. Confirm whether `circuit_open` is true for the primary provider.
3. Check request logs for retryable 5xx/429 or dispatch errors.
4. Reduce traffic or lower per-key request limits if the provider is rate limiting.
5. Temporarily disable an unhealthy provider in config and validate before restart.

Token budget exhaustion:

1. Check API key usage aggregates.
2. Confirm whether failures return `token_budget_exceeded`.
3. Increase `monthly_token_budget` only after confirming ownership and expected usage.
4. Prefer adding a separate API key for bursty workloads instead of raising a shared key budget.

TLS startup failure:

1. Run `ferrogate validate --config /etc/ferrogate/ferrogate.toml`.
2. For manual TLS, confirm `cert_path` and `key_path` are readable by the service user and the certificate chain matches the private key.
3. For ACME DNS-01, confirm `storage_dir` is writable, DNS hooks are executable, the hook can create and delete the TXT record, and DNS propagation is long enough for the authoritative DNS provider.
4. Restart or perform a graceful upgrade after replacing manual files or changing ACME listener settings.

High memory growth:

1. Disable request body logging.
2. Reduce streaming concurrency or add more instances.
3. Check active client timeouts and provider timeouts.
4. Inspect whether clients are abandoning streaming responses slowly.

## Current limits

- Durable storage is not yet wired into production deployment.
- Automatic certificate issuance/renewal is not implemented.
- Executable hot reload currently validates candidates and reports snapshot metadata; running config swap is still pending.
- Multi-node deployments need external load balancing and shared policy around API key/config distribution.
