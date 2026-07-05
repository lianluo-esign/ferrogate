<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-06-11
  description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.
-->

# Kubernetes Deployment Examples

These manifests are reference examples for self-hosted FerroGate clusters.
They intentionally use placeholder secrets and a small Redis Deployment so a
test cluster can run the full example with:

```bash
kubectl apply -f deploy/kubernetes
```

Production deployments should replace `ferrogate-secret` values through a
secret manager, use managed or highly available Redis, and choose storage
classes that support the access modes requested by the PVCs.

The runtime contract maps directly to FerroGate behavior:

- `/healthz` is the liveness probe.
- `/readyz` is the readiness probe and fails while the node is draining.
- `preStop` calls `POST /admin/v1/drain`, then sleeps before termination.
- `FERROGATE_NODE_ID` is populated from the Pod name and resolves
  `cluster.node_id = "auto"`.
- `/metrics` is exposed on the Service with Prometheus scrape annotations.
- provider, client, and admin secrets are read from environment variables, not
  from the ConfigMap.

Vector observability examples live under `deploy/vector/`:

- `vector.yaml` receives FerroGate OTLP HTTP/gRPC logs, metrics, and traces,
  and also scrapes `/metrics` through Vector's Prometheus scrape source.
- `ferrogate-observability.yaml` shows the equivalent FerroGate
  observability settings for enabling Vector without making Vector a required
  runtime dependency or billing provider.

ACME storage is mounted at `/var/lib/ferrogate/acme`. The example keeps ACME
disabled in `ferrogate.toml`; enable it only after mounting durable storage and
setting real domains, email, and DNS provider credentials.

`admin-console.yaml` deploys the admin console frontend as a separate,
stateless workload: no secrets, no PVCs, no `/metrics` (it's a static SPA
served by nginx, health-checked at `/healthz`). It has its own Ingress on a
distinct host (`admin.ferrogate.example.com` by default) since it calls the
`ferrogate` and `ferrogate-auth` Services cross-origin — both of those need
CORS configured for that host before the console will work.
