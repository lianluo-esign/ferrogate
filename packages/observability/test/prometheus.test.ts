import { describe, expect, test } from "vitest";
import {
  defaultGatewayMetricsSnapshot,
  renderPrometheusText,
  renderUnjoinableActionsText,
  type GatewayMetricsSnapshot,
  type UnjoinableActionMetricTotal,
} from "../src/index.js";

function fullSnapshot(): GatewayMetricsSnapshot {
  return {
    serviceName: "ferrogate",
    requestLogTotal: 2,
    requestErrorTotal: 1,
    requestStatusTotals: [
      { statusCode: 200, count: 1 },
      { statusCode: 429, count: 1 },
    ],
    cacheHitsTotal: 1,
    cacheMissesTotal: 1,
    semanticCacheHitsTotal: 1,
    guardrailMatchTotal: 2,
    guardrailDenialTotal: 1,
    guardrailRedactionTotal: 1,
    guardrailDetectorErrorTotal: 3,
    guardrailEvaluationTotal: 5,
    guardrailEvaluationFailTotal: 2,
    guardrailEvaluationErrorTotal: 1,
    guardrailEvaluationShadowTotal: 2,
    guardrailEvidencePersistenceFailureTotal: 1,
    guardrailPolicyCasConflictTotal: 2,
    billingEventTotal: 1,
    billingReportEnqueueFailureTotal: 1,
    toolCallTotal: 2,
    toolLatencyMsTotal: 17,
    mcpIdentityResolutionTotal: 5,
    mcpIdentityFailureTotal: 1,
    mcpIdentityRefreshTotal: 2,
    mcpIdentityRevocationTotal: 1,
    mcpRefreshResponseDeadlineTotal: 3,
    mcpRefreshStorageCancellationTotal: 2,
    mcpRefreshStorageOutcomeUnknownTotal: 4,
    mcpRefreshLateReconciliationTotal: 1,
    mcpIdentityErrorAuditDeadlineTotal: 4,
    postgresPoolAcquireTotal: 7,
    postgresPoolAcquireTimeoutTotal: 2,
    postgresPoolAcquireWaitMicrosTotal: 1_500_000,
    evidenceWriterEnqueuedTotal: 9,
    evidenceWriterWrittenTotal: 8,
    evidenceWriterDroppedTotal: 1,
    tokenTotals: { promptTokens: 3, completionTokens: 5, totalTokens: 8 },
    modelProviderTotals: [
      {
        logicalModel: "fast-chat",
        provider: "openai",
        requests: 1,
        totalTokens: 8,
      },
    ],
    mcpMethodTotals: [
      { method: "tools/call", name: "srv-search", requests: 3 },
    ],
    networkAccessDeniedTotal: 3,
    networkAccessRateLimitedTotal: 4,
    assetLifecycleScannedTotal: 7,
    assetLifecyclePrunedTotal: 5,
    assetLifecycleFailedTotal: 1,
    assetPresignIntentIssuedTotal: 11,
    assetPresignIntentRejectedTotal: 2,
    assetPresignBucketRejectedTotal: 3,
    assetPresignStagingMissingTotal: 4,
    assetPresignCommitRejectedTotal: 5,
    assetPresignAbortedTotal: 6,
    assetPresignAbortReclaimFailedTotal: 2,
  };
}

describe("renderPrometheusText", () => {
  test("renders the full gateway metrics snapshot", () => {
    const text = renderPrometheusText(fullSnapshot());

    const expected = [
      "# TYPE ferrogate_request_logs_total counter",
      "ferrogate_request_errors_total 1",
      'ferrogate_request_status_total{status_code="200"} 1',
      'ferrogate_request_status_total{status_code="429"} 1',
      'ferrogate_ai_cache_requests_total{status="hit"} 1',
      'ferrogate_ai_cache_requests_total{status="miss"} 1',
      'ferrogate_ai_cache_requests_total{status="semantic_hit"} 1',
      "ferrogate_guardrail_matches_total 2",
      "ferrogate_guardrail_denials_total 1",
      "ferrogate_guardrail_redactions_total 1",
      "ferrogate_guardrail_detector_errors_total 3",
      'ferrogate_guardrail_evaluations_total{verdict="pass"} 2',
      'ferrogate_guardrail_evaluations_total{verdict="fail"} 2',
      'ferrogate_guardrail_evaluations_total{verdict="error"} 1',
      "ferrogate_guardrail_shadow_evaluations_total 2",
      "ferrogate_guardrail_evidence_persistence_failures_total 1",
      "ferrogate_guardrail_policy_cas_conflicts_total 2",
      "ferrogate_network_access_denied_total 3",
      "ferrogate_network_access_rate_limited_total 4",
      "ferrogate_asset_lifecycle_scanned_total 7",
      "ferrogate_asset_lifecycle_pruned_total 5",
      "ferrogate_asset_lifecycle_failed_total 1",
      "ferrogate_asset_presign_intents_issued_total 11",
      'ferrogate_asset_presign_rejected_total{stage="intent"} 2',
      'ferrogate_asset_presign_rejected_total{stage="bucket"} 3',
      'ferrogate_asset_presign_rejected_total{stage="commit"} 5',
      "ferrogate_asset_presign_staging_missing_total 4",
      "ferrogate_asset_presign_aborted_total 6",
      "ferrogate_asset_presign_abort_reclaim_failed_total 2",
      "ferrogate_billing_report_enqueue_failures_total 1",
      "ferrogate_mcp_tool_calls_total 2",
      "ferrogate_mcp_tool_latency_ms_total 17",
      "ferrogate_mcp_identity_resolutions_total 5",
      "ferrogate_mcp_identity_failures_total 1",
      "ferrogate_mcp_identity_refreshes_total 2",
      "ferrogate_mcp_identity_revocations_total 1",
      "ferrogate_mcp_refresh_response_deadlines_total 3",
      "ferrogate_mcp_refresh_storage_cancellations_total 2",
      "ferrogate_mcp_refresh_storage_outcome_unknown_total 4",
      "ferrogate_postgres_pool_acquires_total 7",
      "ferrogate_postgres_pool_acquire_timeouts_total 2",
      "ferrogate_postgres_pool_acquire_wait_seconds_total 1.5",
      "ferrogate_evidence_writer_enqueued_total 9",
      "ferrogate_evidence_writer_written_total 8",
      "ferrogate_evidence_writer_dropped_total 1",
      "ferrogate_mcp_refresh_late_reconciliations_total 1",
      "ferrogate_mcp_identity_error_audit_deadlines_total 4",
      'ferrogate_tokens_total{type="total"} 8',
      'ferrogate_model_provider_requests_total{logical_model="fast-chat",provider="openai"} 1',
      'ferrogate_mcp_requests_total{method="tools/call",name="srv-search"} 3',
    ];
    for (const line of expected) {
      expect(text).toContain(line);
    }
  });

  test("info gauge carries the escaped service label", () => {
    const text = renderPrometheusText({
      ...fullSnapshot(),
      serviceName: 'ac"me',
    });
    expect(text).toContain('ferrogate_info{service="ac\\"me"} 1');
  });

  test("pass verdict saturates rather than underflowing", () => {
    const text = renderPrometheusText({
      ...fullSnapshot(),
      guardrailEvaluationTotal: 1,
      guardrailEvaluationFailTotal: 2,
      guardrailEvaluationErrorTotal: 5,
    });
    expect(text).toContain('ferrogate_guardrail_evaluations_total{verdict="pass"} 0');
  });
});

describe("renderUnjoinableActionsText", () => {
  test("renders one low-cardinality tenant/surface counter per total (#522/#500)", () => {
    const totals: UnjoinableActionMetricTotal[] = [
      { tenant: "tenant-a", surface: "mcp", requests: 2 },
      { tenant: "tenant-b", surface: "asset", requests: 5 },
    ];
    const text = renderUnjoinableActionsText(totals);

    expect(text).toContain("# TYPE ferrogate_unjoinable_actions_total counter");
    expect(text).toContain(
      'ferrogate_unjoinable_actions_total{tenant="tenant-a",surface="mcp"} 2',
    );
    expect(text).toContain(
      'ferrogate_unjoinable_actions_total{tenant="tenant-b",surface="asset"} 5',
    );
    // The declared/absent id must never become a label. (The HELP line
    // legitimately mentions `x-ferrogate-agent-run-id` descriptively, so we
    // assert on the label form, not a bare substring.) Only tenant/surface
    // labels may appear on the counter series.
    expect(text).not.toContain("agent_run_id");
    expect(text).not.toMatch(/\{[^}]*run[_-]?id\s*=/);
    for (const line of text.split("\n")) {
      if (line.startsWith("ferrogate_unjoinable_actions_total{")) {
        const labels = line.slice(
          line.indexOf("{") + 1,
          line.indexOf("}"),
        );
        const keys = labels
          .split(",")
          .map((pair) => pair.split("=")[0]?.trim());
        expect(keys).toEqual(["tenant", "surface"]);
      }
    }
  });

  test("empty totals still render the HELP/TYPE header", () => {
    const text = renderUnjoinableActionsText([]);
    expect(text).toContain("# TYPE ferrogate_unjoinable_actions_total counter");
    expect(text.trim().endsWith("counter")).toBe(true);
  });
});

/**
 * PLATFORM LIMIT PIN — kept as a PORT-TODO in `src/prometheus.ts`.
 *
 * A Worker has no long-lived process to accumulate counters in, so this module
 * deliberately holds NO state: it is a pure snapshot→text function and the
 * accumulation is the composition root's problem (a Durable Object, or an
 * Analytics Engine read). These assertions are what stops someone "closing" the
 * marker by adding a module-scope counter bag, which would look like a port and
 * silently under-report — each isolate would render only its own slice.
 */
describe("PLATFORM LIMIT — the renderer accumulates nothing", () => {
  test("rendering is pure: the same snapshot renders identically, forever", () => {
    const snapshot = { ...defaultGatewayMetricsSnapshot(), requestLogTotal: 5 };
    const first = renderPrometheusText(snapshot);
    const second = renderPrometheusText(snapshot);
    const third = renderPrometheusText(snapshot);
    expect(second).toBe(first);
    expect(third).toBe(first);
  });

  test("a second render does not accumulate the first snapshot's totals", () => {
    // If this module ever grew internal counters, `requestLogTotal` would climb
    // across calls and this would fail — which is exactly the intent.
    const a = renderPrometheusText({ ...defaultGatewayMetricsSnapshot(), requestLogTotal: 3 });
    const b = renderPrometheusText({ ...defaultGatewayMetricsSnapshot(), requestLogTotal: 3 });
    expect(a).toContain("ferrogate_request_logs_total 3\n");
    expect(b).toContain("ferrogate_request_logs_total 3\n");
  });
});
