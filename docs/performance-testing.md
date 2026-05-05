# FerroGate Performance Testing

This document defines the manual performance-report workflow for high-load
gateway validation. The regular CI job keeps fast smoke coverage; this workflow
is for dedicated load-test hosts because 10k connections and 20k-100k RPS can
exhaust developer laptops or shared CI runners.

## What It Measures

The report workflow covers the scenarios that matter for gateway capacity
planning:

- 10k open connections against a FerroGate HTTP endpoint.
- Staged target request rates: 20k, 50k, and 100k requests per second.
- Five-minute sustained stages for stability observation.
- FerroGate process CPU and RSS sampling during the full run.
- Per-second latency curves with p50, p95, p99, and max latency.
- Raw Vegeta result files for deeper post-processing.

## Required Tools

Install these on the load-test host:

```bash
vegeta version
jq --version
awk --version
```

Raise file descriptor limits before opening 10k connections:

```bash
ulimit -n 1048576
```

On Linux load-test machines, also review ephemeral port and backlog settings
before running 50k-100k RPS from a single host:

```bash
sysctl net.ipv4.ip_local_port_range
sysctl net.ipv4.tcp_tw_reuse
sysctl net.core.somaxconn
```

## Reverse Proxy Report

Start a local upstream service, start FerroGate with a route to that upstream,
then run:

```bash
scripts/perf-gateway-report.sh \
  --url http://127.0.0.1:8088/local/proxy-check \
  --pid "$(pgrep -n ferrogate)" \
  --connections 10000 \
  --rates 20000,50000,100000 \
  --duration 5m
```

For a lightweight validation of the script itself:

```bash
scripts/perf-gateway-report.sh \
  --url http://127.0.0.1:8088/local/proxy-check \
  --rates 10,25 \
  --connections 16 \
  --duration 10s
```

## AI Gateway Report

Create a request body:

```bash
cat > /tmp/ferrogate-chat-body.json <<'JSON'
{"model":"fast-chat","messages":[{"role":"user","content":"hello"}]}
JSON
```

Run the staged report:

```bash
scripts/perf-gateway-report.sh \
  --url http://127.0.0.1:8080/v1/chat/completions \
  --method POST \
  --header 'Authorization: Bearer dev-secret' \
  --header 'Content-Type: application/json' \
  --body-file /tmp/ferrogate-chat-body.json \
  --pid "$(pgrep -n ferrogate)" \
  --connections 10000 \
  --rates 20000,50000,100000 \
  --duration 5m
```

Use a local provider stub for this test. Do not point this profile at paid
external model providers unless the budget impact is intentional.

## Report Artifacts

By default reports are written under `perf-reports/<UTC timestamp>/`.

Important files:

- `summary.md`: human-readable stage summary.
- `process-metrics.csv`: timestamped CPU and RSS samples.
- `stages.csv`: stage index with paths to generated artifacts.
- `rps-*.aggregate.json`: aggregate Vegeta metrics for each stage.
- `rps-*.latency-curve.csv`: per-second p50/p95/p99/max latency curve.
- `rps-*.histogram.txt`: latency histogram.
- `rps-*.plot.html`: Vegeta HTML plot.
- `rps-*.bin`: raw Vegeta binary results.

## Interpreting Results

Treat a run as suspicious when:

- Achieved RPS is materially below target while CPU is saturated.
- Success rate drops below `1.0`.
- p99 or max latency trends upward across the 5-minute stage.
- RSS grows monotonically and does not stabilize after warmup.
- CPU climbs over time at a fixed RPS without a matching throughput increase.

Use the latency curve CSVs to draw the time-series view. A stable stage should
show mostly flat p95/p99 after warmup. A rising p99 curve under fixed RPS is a
stronger regression signal than a single aggregate p99 number.

## Why This Is Not In CI

The repository CI still runs:

```bash
cargo test -p ferrogate-cli --test runtime_perf --test ai_proxy_perf -- --nocapture
```

Those tests are fast performance smoke checks. The 10k-connection, 100k RPS,
five-minute report is intentionally manual because it requires dedicated host
capacity, kernel tuning, and a controlled network path.
