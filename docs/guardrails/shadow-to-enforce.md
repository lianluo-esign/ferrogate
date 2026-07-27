# Shadow → enforce promotion and rollback (guardrail policies, #201)

The decision procedure for qualifying a semantic security adapter (Presidio
DLP/PII, LLM-Guard prompt injection — see `docs/guardrails/adapters/`) and
moving it from **shadow observation** to **live enforcement**, with a safe
rollback path. Every step below is deterministic and covered by tests; no live
vendor endpoint is required to exercise the loop — only to run it against real
production traffic.

The loop has four stages:

```
  ┌──────────┐   ┌───────────────────┐   ┌───────────────┐   ┌──────────┐
  │  shadow  │──▶│ compare to human  │──▶│ promote by    │──▶│ rollback │
  │  sample  │   │ labels (score)    │   │ scope         │   │ trigger  │
  └──────────┘   └───────────────────┘   └───────────────┘   └──────────┘
```

## 1. Shadow sample — record evidence, enforce nothing

A guardrail policy revision runs in shadow when its `mode` is `shadow`
(`PolicyMode::Shadow`). In shadow mode the detector still runs and its verdict
is written to durable evidence, but **no enforcement candidate is produced** —
the request is never blocked or redacted. The recorded evidence rows carry
`enforcement_status: "shadow_only"` and `verdict: "pass" | "fail" | "error"`.

Create and activate a shadow revision exactly like any other immutable
revision (immutability from #196):

```text
create_guardrail_policy_revision(revision { mode: shadow, scope, checks, … })
activate_guardrail_policy_revision(policy_id, revision, actor, ts, rollback_only=false)
```

Because the revision is scoped (`PolicyScopeSelector`), you can shadow a new
adapter for one organization / project / model / API key while the rest of the
fleet is unaffected — this is the same selector used later to promote by scope.

The scoring input is a set of **shadow observations**: one recorded verdict per
labelled example. In code
(`ferrogate_guardrails::evaluation`, feature `conformance` / `cfg(test)`):

```rust
pub struct ShadowObservation {
    pub case_id: String,          // links the verdict to a human label
    pub expected_malicious: bool, // the human label
    pub outcome: ShadowOutcome,   // Flagged | Cleared | Errored
}
```

`ShadowOutcome::from_result(&detector_result)` maps a detector verdict to an
observation the same way the live runner does (`Fail` → `Flagged`, any other
verdict → `Cleared`, an error → `Errored`). `record_shadow_observations(detector,
corpus)` produces a full set offline (used in tests to drive the whole loop
without a network).

## 2. Compare to human labels — score

The evaluation corpus (`EvaluationCorpus` / `EvaluationCase`) **is** the set of
human labels: each case carries `expected_malicious`. Scoring the recorded
shadow verdicts against those labels reuses the same confusion-matrix core as
the live accuracy runner, so a scored shadow run and a live run over the same
corpus produce identical precision / recall / F1 / triage lists:

```rust
let metrics = score_shadow_observations(corpus_version, &observations);
// -> EvaluationMetrics { precision, recall, f1, false_positive_cases,
//                        false_negative_cases, error_cases, … }
```

`score_shadow_observations` never re-runs the detector and never touches live
traffic — it scores evidence already recorded in shadow. Metrics carry only
case ids and descriptions, never raw matched content.

## 3. Promote by scope — the gate

A `PromotionGate` turns metrics into a promote/hold decision against an explicit
bar (`PromotionThresholds`):

```rust
let gate = PromotionGate::new(PromotionThresholds::conservative());
match gate.assess_shadow(&metrics) {
    PromotionDecision::Promote      => { /* create + activate an `enforce` revision */ }
    PromotionDecision::Hold { unmet } => { /* keep shadowing; `unmet` says why */ }
}
```

`PromotionThresholds` fields:

| Field | Guards against | Notes |
|---|---|---|
| `min_precision` | blocking legitimate traffic (false positives) | |
| `min_recall` | letting attacks through (false negatives) | |
| `min_f1` | a lopsided precision/recall trade | |
| `max_error_rate` | promoting a flaky detector | `errors / total` |
| `rollback_min_precision` | — | looser floor used in stage 4 |
| `rollback_min_recall` | — | looser floor used in stage 4 |

The bar is chosen per adapter role. A **PII engine** (Presidio) is judged on
precision and its own PII recall; an **injection scanner** (LLM-Guard) tolerates
some false positives in exchange for recall. Judging Presidio by an
injection-recall bar correctly **holds** it (a DLP engine catches no
injections, by design) — the gate refuses to promote a detector outside its
competence.

On a `Promote`, promotion is just the activation of a new immutable revision
whose `mode` is `enforce` and whose `scope` is the same selector you shadowed
under (widen the scope deliberately to roll enforcement out further):

```text
create_guardrail_policy_revision(revision { mode: enforce, scope, on_fail: [block …], … })
activate_guardrail_policy_revision(policy_id, new_revision, actor, ts, rollback_only=false)
```

## 4. Rollback trigger

An enforced revision is watched with the **looser** rollback floors (hysteresis:
a revision is only rolled back on a genuine regression, not on the noise that
would merely have held promotion):

```rust
match gate.assess_enforced(&fresh_metrics) {
    RollbackDecision::Keep => { /* still healthy */ }
    RollbackDecision::Rollback { regressions } => { /* roll back, `regressions` says why */ }
}
```

Rollback re-activates the prior revision with the `rollback_only` flag set — the
same immutable-revision machinery, which archives the regressed revision and
restores the binding atomically (and restores it again if the runtime reload
fails):

```text
activate_guardrail_policy_revision(policy_id, prior_revision, actor, ts, rollback_only=true)
```

After a rollback to the prior shadow revision, the policy stops enforcing and
returns to recording-only — a safe state from which to diagnose and re-qualify.

## Where this lives

| Piece | Location |
|---|---|
| `PolicyMode::Shadow` / `enforced` / scoped selection | `crates/ferrogate-guardrails/src/policy.rs` |
| Shadow evidence (`enforcement_status`) | `crates/ferrogate-gateway/src/state_quota_and_policy.rs` |
| Immutable revisions, activate, rollback | `crates/ferrogate-gateway/src/state.rs` (`activate_guardrail_policy_revision`) |
| `ShadowObservation` / `score_shadow_observations` / `PromotionGate` | `crates/ferrogate-guardrails/src/evaluation.rs` |
| Evaluation corpus = human labels | `crates/ferrogate-guardrails/src/evaluation.rs` (`EvaluationCorpus`) |

## Tests that exercise the full loop

- `crates/ferrogate-guardrails/src/adapters_test.rs`
  - `llm_guard_shadow_scores_against_labels_and_promotion_gate_promotes_then_rollback`
    — LLM-Guard shadow-samples the corpus, is scored against the labels,
    cleared by an injection bar to promote, then a regression trips rollback.
  - `presidio_shadow_is_held_when_judged_by_an_injection_recall_bar` — the gate
    refuses to promote a PII engine on an injection bar.
- `crates/ferrogate-guardrails/src/evaluation_test.rs` — scoring parity with a
  live run, verdict mapping, and the promote / hold / rollback gate decisions.
- `crates/ferrogate-gateway/src/state_quota_and_policy_test.rs`
  - `shadow_revision_records_evidence_then_promotes_by_scope_and_rolls_back` —
    the loop at the policy layer: a shadow revision records `shadow_only`
    evidence and does not block; a scoped enforce revision is promoted and
    blocks; a rollback to the prior shadow revision stops enforcing.
