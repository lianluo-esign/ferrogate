# FerroGate

**The open-source Rust gateway for AI traffic.**

FerroGate is an open-source AI gateway and reverse proxy written in Rust. It is designed to route, secure, monitor, and control traffic to LLM providers such as OpenAI, Anthropic, Google Gemini, Azure OpenAI, and OpenAI-compatible APIs.

Built by the team behind [Token4AI Cloud](https://token4ai.cloud), a managed platform for AI usage analytics, billing, and governance.

## Project naming

| Item | Value |
| --- | --- |
| Project display name | FerroGate |
| GitHub repo | `ferrogate` |
| Rust crate | `ferrogate` |
| CLI binary | `ferrogate` |
| Docker image | `ghcr.io/lianluo-esign/ferrogate` |
| Config file | `ferrogate.toml` |
| Website path | <https://token4ai.cloud/ferrogate> |

## Goals

- Open-source Rust API Gateway and AI Gateway for AI traffic
- Built-in API gateway capabilities inspired by mature gateway products
- Reverse proxy foundation for HTTP services
- Virtual API keys, tenant context, and model allowlists
- Provider routing and OpenAI-compatible API surface
- Token control, usage observability, and policy hooks
- Production-friendly Rust implementation

## Current status

FerroGate is in early development. The current MVP implements:

- Cloudflare Pingora-based gateway runtime
- `GET /healthz` health check
- `GET /v1/models` OpenAI-compatible model list from config
- `POST /v1/chat/completions` request validation, virtual API key auth, tenant context resolution, and model routing placeholder
- `GET /admin/status` gateway status summary
- Generic reverse proxy with configured upstreams/routes
- Path prefix routing and path rewrite (`strip_prefix`/`add_prefix`)
- Request header forwarding and configured header injection
- TOML configuration loading and validation
- Provider registry, model registry, and virtual API key config
- CLI commands for serving and config validation
- `x-request-id` propagation/generation and structured gateway logs

Upstream proxying to AI providers, streaming, and production-grade Pingora load balancing/failover are the next implementation milestones.

## Quick start

```bash
cargo run -- --config ./config/ferrogate.example.toml check
cargo run -- --config ./config/ferrogate.example.toml serve
```

Then open:

```bash
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/proxy/httpbin/get
curl -H 'Authorization: Bearer dev-secret' http://127.0.0.1:8080/v1/models
curl -H 'Authorization: Bearer dev-secret' http://127.0.0.1:8080/admin/status
```

Try the chat completion routing placeholder:

```bash
curl -X POST http://127.0.0.1:8080/v1/chat/completions \
  -H 'Authorization: Bearer dev-secret' \
  -H 'Content-Type: application/json' \
  -d '{"model":"fast-chat","messages":[{"role":"user","content":"hello"}]}'
```

## Configuration

FerroGate loads `ferrogate.toml` by default. You can also pass a custom path:

```bash
ferrogate --config ./config/ferrogate.example.toml check
ferrogate --config ./config/ferrogate.example.toml serve
```

Example:

```toml
listen = "127.0.0.1:8080"

[[providers]]
name = "openai"
base_url = "https://api.openai.com/v1"
api_key_env = "OPENAI_API_KEY"
```

## Docker

```bash
docker build -t ferrogate .
docker run --rm -p 8080:8080 ferrogate
```

## Documentation wiki

The project wiki now lives in a standalone monorepo: [`ferrogate-wiki`](https://github.com/lianluo-esign/ferrogate-wiki).

This repository keeps it available as a submodule at [`ferrogate-wiki/`](ferrogate-wiki/), containing:

- `wiki/`: Obsidian vault and Markdown source of truth
- `wiki-site/`: Quartz static site generator project
- `scripts/build-wiki-site.sh`: build, serve, and clean entrypoint

Clone this repository with submodules:

```bash
git clone --recurse-submodules https://github.com/lianluo-esign/ferrogate.git
```

Or initialize the wiki submodule after cloning:

```bash
git submodule update --init --recursive
```

Build the wiki site from the submodule:

```bash
cd ferrogate-wiki
./scripts/build-wiki-site.sh build
```

Preview it locally:

```bash
cd ferrogate-wiki
./scripts/build-wiki-site.sh serve
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
