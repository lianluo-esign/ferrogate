# FerroGate Roadmap

## Milestone 1: Gateway core

- HTTP server lifecycle
- Configuration loading and validation
- Health checks
- OpenAI-compatible route skeleton

## Milestone 2: AI provider proxying

- OpenAI-compatible chat completions proxy
- Provider credentials from environment variables
- Streaming response support
- Request and response tracing

## Milestone 3: Traffic governance

- API key authentication
- Rate limiting
- Token usage accounting hooks
- Provider fallback and routing policies

## Milestone 4: Edge and Caddy-inspired features

- Reverse proxy for generic HTTP services
- Automatic HTTPS support
- Hot config reload
- Docker and Kubernetes deployment examples
