<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-06-11
  description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.
-->

# FerroGate Helm Chart

This chart deploys FerroGate with the same runtime contract as the static
Kubernetes examples:

- `/healthz` for liveness and `/readyz` for readiness.
- `preStop` drain through `POST /admin/v1/drain`.
- Pod-name based node identity through `FERROGATE_NODE_ID`.
- Config in a ConfigMap and secrets in a Secret or externally managed Secret.
- Optional Redis, shared state PVC, ACME PVC, Service, and Ingress.

Render locally:

```bash
helm template ferrogate charts/ferrogate
```

Install with externally managed secrets:

```bash
helm upgrade --install ferrogate charts/ferrogate \
  --set secrets.create=false \
  --set secrets.name=ferrogate-secret \
  --set image.tag=v2026.06.07
```

Do not leave the default placeholder secret values in a production namespace.
