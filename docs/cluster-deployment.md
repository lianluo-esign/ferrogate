---
title: Cluster Deployment
description: Scheduler-agnostic deployment guidance for FerroGate cluster mode.
permalink: /cluster-deployment/
---

# Cluster Deployment

FerroGate cluster mode is Kubernetes-first, not Kubernetes-only. Kubernetes can
run replicas, probes, secrets, Services, and rolling updates, but the gateway
cluster contract is owned by FerroGate runtime state:

- each node advertises `cluster_id`, `node_id`, region, zone, state backend,
  counter backend, active revision, sync error, stale state, and drain state;
- `/readyz` only reports ready when the node has a valid state revision and is
  not draining;
- `/admin/v1/drain` lets an operator stop new work before terminating a node;
- `state_backend = "file"` can share lightweight API key and policy state
  through a durable shared file;
- `counter_backend = "redis"` enforces API-key request limits and token-budget
  reservations across nodes with atomic Redis counters;
- request logs, audit events, metering events, and provider health expose
  cluster and node identity so operators can debug by replica.

Kubernetes examples and a future Helm chart belong to issue #19. This document
defines the runtime deployment contract that should work the same way on
Kubernetes, ECS/Fargate, Nomad, Docker/systemd on VMs, and private on-prem
schedulers.

## Minimum Cluster Contract

Every production cluster should provide:

- two or more FerroGate replicas behind a load balancer;
- unique `cluster.node_id` per replica, with one shared `cluster.cluster_id`;
- one shared state location when using `cluster.state_backend = "file"`;
- Redis when `cluster.counter_backend = "redis"` is required for cluster-safe
  quota and token-budget enforcement;
- `/healthz` for process liveness and `/readyz` for load-balancer readiness;
- a drain step before rolling restart or host shutdown;
- Prometheus or OTLP scraping/export with `cluster_id` and `node_id` labels or
  attributes preserved.

Current supported backends are deliberately small:

```toml
[cluster]
enabled = true
cluster_id = "prod-us"
node_id = "gateway-a"
node_region = "us-east-1"
node_zone = "us-east-1a"

# local is process-local. file uses a shared JSON file for lightweight
# multi-node API key and policy propagation.
state_backend = "file"
file_state_path = "/var/lib/ferrogate/cluster-state.json"

# local is process-local. redis is required for cluster-safe request limits and
# token-budget reservation/settlement across replicas.
counter_backend = "redis"
redis_url = "redis://redis:6379/0"
counter_timeout_millis = 500

heartbeat_interval_secs = 10
config_poll_interval_secs = 5
```

Use `state_backend = "local"` only when every replica is intentionally managed
from the same immutable config and Admin writes do not need to propagate across
nodes. Use `counter_backend = "local"` only for single-node deployments or
development.

## Kubernetes Path

Kubernetes should map the contract this way:

- run FerroGate as a Deployment or StatefulSet with at least two replicas;
- mount the FerroGate config from a ConfigMap and provider credentials from
  Secrets;
- set `cluster.node_id` from the pod name when stable per-pod identity matters;
- use `readinessProbe` against `/readyz` and `livenessProbe` against
  `/healthz`;
- use `preStop` to enable drain through `/admin/v1/drain`, then sleep long
  enough for configured graceful shutdown windows;
- run Redis as a managed service or separate highly available deployment when
  cluster-safe counters are enabled;
- use a ReadWriteMany volume or a managed shared file service only if using the
  lightweight file state backend;
- expose `/metrics` to Prometheus and keep `cluster_id` and `node_id` labels.

Kubernetes does not replace FerroGate cluster state. It schedules and restarts
processes; it does not provide shared API key propagation, revision validation,
distributed token-budget reservations, or gateway audit/billing aggregation by
itself.

## Non-Kubernetes Paths

The same runtime contract works without Kubernetes.

### ECS/Fargate

- Run at least two tasks behind an Application Load Balancer or Network Load
  Balancer.
- Use the task metadata endpoint or injected environment to render a unique
  `cluster.node_id`.
- Store config in the task definition, mounted volume, or sidecar-rendered file;
  store provider secrets in Secrets Manager or SSM Parameter Store.
- Point ALB health checks to `/readyz`.
- Use task draining plus a shutdown hook that calls `/admin/v1/drain` before
  sending SIGTERM.
- Use ElastiCache Redis for `counter_backend = "redis"`.

### Nomad

- Run FerroGate as a service job with two or more allocations.
- Render config through templates and set `cluster.node_id` from Nomad
  allocation metadata.
- Register `/readyz` as the service check and `/healthz` as a process check.
- Use Consul or another load balancer to route only ready allocations.
- Use task lifecycle hooks to enable drain before restart.
- Use external Redis for shared counters and a shared volume only when file
  state propagation is needed.

### Docker Or Systemd On VMs

- Run one FerroGate process per VM or container and put them behind HAProxy,
  NGINX, Caddy, or a cloud load balancer.
- Keep `cluster.cluster_id` identical and configure a unique `cluster.node_id`
  per host.
- Mount the same durable `file_state_path` on all nodes only when using file
  state propagation.
- Configure the load balancer to remove a node when `/readyz` is not 200.
- Before maintenance, call `/admin/v1/drain` on the node, wait for active
  requests to finish, then stop the service.
- Use an external Redis instance for cluster-safe request and token counters.

## Rolling Restart Sequence

Use the same sequence on every scheduler:

1. Enable drain on one node with `POST /admin/v1/drain`.
2. Wait until the load balancer stops sending new requests to that node.
3. Let in-flight streaming requests finish within the configured graceful
   shutdown window.
4. Stop or replace the node.
5. Wait for the new node to return `/readyz` 200 with the expected
   `cluster_id`, unique `node_id`, active revision, and no sync error.
6. Move to the next node.

Do not use `/healthz` as the only readiness signal. A process can be alive while
it is draining, missing a shared state revision, or unable to reach the shared
state backend at startup.

## Failure Semantics

- Startup without a valid shared state revision fails readiness unless the node
  is using a valid configured local fallback.
- Losing shared state after a valid revision has already loaded keeps serving
  the last valid revision and reports stale state.
- Redis counter failures fail closed for guarded AI requests when Redis is the
  configured counter backend.
- Provider health currently separates local node observations from nullable
  cluster aggregate observations. A null aggregate means no shared aggregation
  backend is configured.

These semantics keep cluster mode lightweight while making the operational
boundary explicit: schedulers own process placement, FerroGate owns gateway
state, quota, readiness, drain, and audit visibility.
