# Single-tenant Durable Object throughput harness

Issue #829 measurement, collected on 2026-08-06 with the local `vitest-pool-workers`
workerd runtime.

## Re-run

From the repository root:

```sh
cd packages/storage
bunx vitest run --config vitest.do.config.ts test/do/tenant-throughput-harness.test.ts --reporter verbose --silent false
```

The test drives one `TenantDataObject` through four load levels (`1`, `4`, `8`, and
`16` concurrent workers). Each worker executes four inference events at each level.
Every event drives five independent RPC paths:

1. Inference metering write: the production-shaped `tenant_contexts`,
   `usage_aggregate_rollups`, and `agent_cost_burn` upserts.
2. Wallet reserve: the production three-statement guarded reservation batch.
3. Usage rollup update: the production-shaped `usage_metadata_rollups` upsert.
4. Asset read: the `stored_assets` projection used by the assets D1 facade.
5. Request-log write: the production `TENANT_REQUEST_LOG_UPSERT_SQL` and binding,
   sent as its own object batch.

The harness resets and seeds only the test object's SQLite database, then verifies
row counts and accumulated values after the sweep. The test asserts the shape of
the result and that every path executed; it intentionally does not assert a
machine-specific throughput threshold. `metrics.json` is the complete emitted
report. `path-metrics.csv` is the same per-run/path data in tabular form.

## Result

This run recorded a no-queue baseline at concurrency 1. The measured baseline was
**125 inference events/sec**, or **625 storage operations/sec** across the five-path
mix, with a whole-mix p99 latency of **11 ms**. The harness defines queueing for
this local sweep as a non-baseline run whose whole-mix p99 exceeds both twice the
baseline p99 and the baseline plus 1 ms; the first such run was concurrency 4.

| Concurrency | Inference events | Storage ops | Inference events/sec | Storage ops/sec | Whole-mix p50/p99 (ms) | Queueing observed |
| ---: | ---: | ---: | ---: | ---: | ---: | :--- |
| 1 | 4 | 20 | 125.00 | 625.00 | 7 / 11 | no |
| 4 | 16 | 80 | 161.62 | 808.08 | 22 / 29 | yes |
| 8 | 32 | 160 | 119.40 | 597.01 | 61 / 102 | yes |
| 16 | 64 | 320 | 185.51 | 927.54 | 73 / 133 | yes |

The aggregate path metrics below cover all 116 inference events in the sweep.
For a specific run's path metrics, use `path-metrics.csv` or the `runs` array in
`metrics.json`.

| Path | Ops | Throughput (ops/sec) | p50 (ms) | p99 (ms) | Wall-time share |
| :--- | ---: | ---: | ---: | ---: | ---: |
| Inference metering write | 116 | 155.91 | 64 | 127 | 19.36% |
| Wallet reserve | 116 | 155.91 | 65 | 127 | 19.59% |
| Usage rollup update | 116 | 155.91 | 66 | 127 | 19.87% |
| Asset read | 116 | 155.91 | 67 | 127 | 20.28% |
| Request-log write | 116 | 155.91 | 68 | 133 | 20.89% |

`latencySharePercent` is the path's share of measured wall-clock operation time,
used here as a local work proxy. The workerd test environment does not expose a
per-RPC CPU profiler, so this is not a claim of production CPU attribution.

## Contention analysis

The equal-weight workload makes the comparison within this run direct: one
operation of each path was issued per inference event. The request-log write was
the largest measured path by total wall-time share (20.89%) and had the highest
aggregate p99 (133 ms). The asset read followed at 20.28%; the usage metadata
rollup was 19.87%; and the inference metering batch, which contains the aggregate
rollup and agent cost burn writes, was 19.36%. These paths formed a tight cluster,
so the data shows shared contention across the high-volume write/read mix rather
than one isolated statement owning the lock.

The wallet reserve path accounted for 19.59% of wall time with a 127 ms p99. It
was not a latency outlier in this equal-weight test, but it remains the lower-volume
money path and stays in its atomic three-statement batch. The harness does not
trade that atomicity for a separate object. The row evidence confirms 116 real
reservations, 116 request logs, one aggregate row, one metadata row, one agent
cost-burn row, and one stored asset row after the sweep.

The inference metering path combines three statements in one measured RPC, so the
harness identifies the combined contention bucket but does not pretend to split
CPU between `usage_aggregate_rollups`, `agent_cost_burn`, and the idempotent
`tenant_contexts` lookup. The separate usage path measures
`usage_metadata_rollups`; request logging is deliberately its own batch because
production writes it separately.

## Interpretation and limits

This is a relative contention measurement in local workerd. It does not reproduce
Cloudflare production placement or establish the documented approximately 1,000
requests/sec soft ceiling for a Durable Object. The absolute production ceiling
requires an authorised deployment measurement. The local no-queue rate above is a
repeatable baseline for this harness and machine, not a production capacity claim.

D1 was also single-threaded per database, so the Durable Object does not regress
the underlying atomicity model. The new risk is that all of one tenant's storage
is now behind one object lock: append-only metering, metadata, cost burn, request
logging, asset reads, and the wallet decision share that serialized object.

No sharding is introduced by this issue. A future shard is justified only if an
actual tenant approaches the measured ceiling in an authorised environment and
the contention data identifies a boundary that preserves the wallet and related
ledger atomicity. Until then, this harness is the measurement gate for deciding
whether sharding is needed at all.
