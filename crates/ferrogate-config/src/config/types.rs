// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub use crate::X402ScopedSpendPolicy;
pub use ferrogate_cloudflare::CloudflareConfig;
pub use ferrogate_core::ApprovalPolicy;
use ferrogate_guardrails::{all_content_sources, ContentSource};
pub use ferrogate_mcp::{
    McpAuthType, McpHeaderConfig, McpOauthConfig, McpServerConfig, McpTlsConfig, McpTransport,
};
use ferrogate_providers::RoutingStrategy;
use ferrogate_storage::{PostgresTlsMode, StorageProviderKind};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default)]
    pub admin: AdminConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub auth_service: AuthServiceConfig,
    #[serde(default)]
    pub billing_service: BillingServiceConfig,
    /// #359: effective FerroGate Control Plane API service config
    /// (`ferrogate control-api serve`), resolved at load from the canonical
    /// `[control_api]` section or the deprecated `[admin_api]` alias below
    /// (never both -- a conflict is rejected). The Rust field keeps its
    /// historical `admin_api` name so the ~150 in-tree accessors are
    /// unchanged, but it is never populated directly from the config file
    /// (`skip_deserializing`) and serializes under the canonical
    /// `control_api` key.
    #[serde(rename = "control_api", skip_deserializing)]
    pub admin_api: AdminApiConfig,
    /// #359: raw canonical `[control_api]` input section. Resolved into
    /// `admin_api` by `migrate_control_plane_aliases` at load; never
    /// serialized (the effective config round-trips through `admin_api`).
    #[serde(default, skip_serializing)]
    pub control_api: Option<AdminApiConfig>,
    /// #359: raw deprecated `[admin_api]` alias section, retained for the
    /// migration window. Resolved into `admin_api` at load (with a
    /// deprecation notice); rejected when `[control_api]` is also present.
    #[serde(rename = "admin_api", default, skip_serializing)]
    pub admin_api_alias: Option<AdminApiConfig>,
    #[serde(default)]
    pub providers: Vec<Provider>,
    #[serde(default)]
    pub models: Vec<Model>,
    #[serde(default)]
    pub api_keys: Vec<ApiKey>,
    #[serde(default)]
    pub policies: Vec<PolicyRule>,
    #[serde(default)]
    pub gateway_configs: Vec<GatewayConfigProfile>,
    #[serde(default)]
    pub agent_workflows: Vec<AgentWorkflowPolicy>,
    #[serde(default)]
    pub skill_packages: Vec<SkillPackage>,
    #[serde(default)]
    pub prompt_templates: Vec<PromptTemplate>,
    #[serde(default)]
    pub guardrails: Vec<GuardrailRule>,
    #[serde(default)]
    pub plugins: Vec<PluginConfig>,
    #[serde(default)]
    pub extensions: Vec<ExtensionConfig>,
    #[serde(default)]
    pub mcp_servers: Vec<McpServerConfig>,
    #[serde(default)]
    pub agent_upstreams: Vec<AgentUpstreamConfig>,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    #[serde(default)]
    pub billing_alerts: BillingAlertsConfig,
    #[serde(default)]
    pub observability: ObservabilityConfig,
    #[serde(default)]
    pub analytics: AnalyticsConfig,
    #[serde(default)]
    pub metering: MeteringConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub reliability: ReliabilityConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub agent_runtime: AgentRuntimeConfig,
    #[serde(default)]
    pub cluster: ClusterConfig,
    #[serde(default)]
    pub upstreams: Vec<Upstream>,
    #[serde(default)]
    pub routes: Vec<RouteRule>,
    #[serde(default)]
    pub network_access: NetworkAccessConfig,
    #[serde(default)]
    pub asset_bucket: AssetBucketConfig,
    #[serde(default)]
    pub scheduler: SchedulerConfig,
    /// #263: asset lifecycle sweeper (version retention + unreferenced-blob GC).
    #[serde(default)]
    pub asset_lifecycle: AssetLifecycleConfig,
    /// #354: background TTL sweeper that releases the wallet hold of an overdue
    /// pre-submission x402 payment attempt.
    #[serde(default)]
    pub x402_sweeper: X402SweeperConfig,
    /// #354: background on-chain settlement reconciler that drives left-behind
    /// `submitted`/`outcome_unknown` attempts to a definite terminal from
    /// on-chain evidence (or keeps them `outcome_unknown` with bounded backoff).
    #[serde(default)]
    pub x402_reconciler: X402ReconcilerConfig,
    /// #351: typed, disabled-by-default Solana x402 spend policies, each pinned
    /// to one scope of the `tenant -> project -> workspace -> key -> run` chain.
    /// Empty (the default) means every scope resolves to the disabled deny-all
    /// policy, so x402 spending is never on by accident. Validated at load by
    /// [`crate::validate_scoped_x402_spend_policies`], which delegates
    /// to the policy crate's own `validate()` so a config that loads is exactly
    /// a config the runtime can evaluate.
    #[serde(default)]
    pub x402_spend_policies: Vec<X402ScopedSpendPolicy>,
    /// #262: asset-egress (download bandwidth) rate in USD per GB used to
    /// settle per-download metering events. `None` (the default) leaves
    /// egress metered + audited but unpriced (cost_usd = None, no wallet
    /// debit) -- exactly how an unpriced model is metered but not charged --
    /// so this is purely additive for a deployment that hasn't opted into
    /// egress billing. Mirrors `PriceBook.egress_price_per_gb`.
    #[serde(default)]
    pub asset_egress_price_per_gb: Option<f64>,
    /// #405: shared Cloudflare API client credentials/config. Absent = every
    /// Cloudflare integration is disabled; present = validated for account
    /// id/token presence and base-URL well-formedness. Non-breaking (serde
    /// default `None`).
    #[serde(default)]
    pub cloudflare: Option<CloudflareConfig>,
    /// #515: how this deployment spells the two tenant-identity defaults that
    /// used to be implicit (platform-root, and whether `organization_id` is a
    /// checked foreign key). See [`TenancyConfig`].
    #[serde(default)]
    pub tenancy: TenancyConfig,
    /// #542: whether this deployment authenticates at all. See [`AuthConfig`];
    /// the default requires authentication.
    #[serde(default)]
    pub auth: AuthConfig,
}

/// Deployment-wide authentication posture (issue #542).
///
/// Before #542 there was no such section: whether the gateway authenticated at
/// all was *inferred* from `auth_service.enabled || !api_keys.is_empty()` --
/// i.e. from the presence of STATIC config credentials. Durable/virtual keys
/// minted through `POST /admin/v1/virtual-keys` and stored in the control plane
/// were not counted, so a deployment whose credentials all live in storage had
/// authentication switched off entirely: `authenticate()` took the "auth
/// disabled" early return, admitted a request that presented no credential at
/// all, and handed back the wildcard scope with `platform_operator: true`.
/// An *omitted* config section granted platform root -- the same defect shape
/// as #515 and #540.
///
/// The inference is gone. Authentication is required unless an operator says
/// otherwise BY NAME, in one field that means exactly one thing.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    /// `false` (the default): every request must present a credential, which is
    /// then resolved against the external auth service, the durable/virtual key
    /// store, and `[[api_keys]]` -- in that order. A request with no credential
    /// is refused, whatever the config happens to contain.
    ///
    /// `true`: authentication is switched OFF deployment-wide and every request
    /// is admitted as an unrestricted platform operator. This is the old
    /// zero-config convenience posture, now reachable only by naming it. It is
    /// appropriate for a laptop, a demo, or a gateway used purely as an L7
    /// reverse proxy on a trusted network -- never for one reachable from
    /// anywhere a credential would have mattered.
    ///
    /// Migration: a deployment that has no credential source at all (no
    /// `[[api_keys]]`, no enabled `[auth_service]`, no durable `[storage]`
    /// backend to hold virtual keys -- see
    /// [`Config::durable_api_key_store`]) used to run in the implicit open
    /// posture. It no longer starts silently: `ferrogate run` refuses with an
    /// error naming this field, so the posture is chosen rather than inherited.
    /// A Caddyfile spells the same thing as `auth off` in the global options
    /// block (`ferrogate-config/src/caddyfile/parser.rs`), because a bridged
    /// config has no `[auth]` section to write it in.
    #[serde(default)]
    pub disabled: bool,
}

impl Config {
    /// The one deployment-wide answer to "must a request present a credential?"
    /// (issue #542). Read by `AppState::auth_required`, by the `ferrogate check`
    /// report and by `/admin/v1/status`, so all three agree by construction
    /// rather than by three hand-copied expressions -- one of which
    /// (`lifecycle::ConfigSummary`) had already drifted, reporting
    /// `auth_required` from `[[api_keys]]` alone and ignoring `[auth_service]`.
    ///
    /// It deliberately does NOT count credentials. Counting them is what made
    /// authentication depend on where a deployment happens to keep its keys:
    /// static keys switched it on, durable/virtual keys in the control plane did
    /// not, and an empty `[[api_keys]]` section switched it off. The posture is
    /// now stated, not inferred, and the safe answer is the default.
    pub fn auth_required(&self) -> bool {
        !self.auth.disabled
    }

    /// Whether this config can resolve a presented credential to *anything*
    /// (issue #542): a static `[[api_keys]]` entry, an enabled external
    /// `[auth_service]`, or a durable `[storage]` backend holding virtual keys
    /// ([`Config::durable_api_key_store`]).
    ///
    /// This is a startup question, not a request-time one -- deliberately so.
    /// The alternative, "authentication is required if the control plane
    /// currently holds an active virtual key", would put a storage read on every
    /// request and would still be wrong: a deployment that booted with zero keys
    /// would stay open until the first key was minted, which is the #542 hole
    /// with an extra step. Whether a request must authenticate is answered by
    /// [`Config::auth_required`] alone; this only decides whether a deployment
    /// that requires authentication has any way to perform it, and is checked
    /// once, at startup, by `gateway::serve` and `execute_control_api_serve`.
    pub fn has_credential_source(&self) -> bool {
        !self.api_keys.is_empty()
            || self.auth_service.enabled
            || self.durable_api_key_store().is_some()
    }

    /// The configured `[storage]` backend, if it is one that can hold durable
    /// virtual API keys -- i.e. one whose control-plane store implements the
    /// `find_api_key_records_by_prefix` lookup the durable authenticator makes
    /// (issue #542 rework).
    ///
    /// Returns the provider itself rather than a bare `bool` so the two callers
    /// that must *name* the key store in operator-facing text -- the "no
    /// credential source" refusal and the `[auth] disabled = true` warning in
    /// `lifecycle::ensure_auth_posture_is_declared` -- cannot drift from the
    /// predicate that decided there was one.
    ///
    /// The match is exhaustive on purpose. The first version of this predicate
    /// spelled the answer as `matches!(provider, Postgres | Supabase)` and
    /// silently omitted `CloudflareD1`, which *is* an implemented durable
    /// control-plane backend (`ferrogate_storage::StorageProviderKind::
    /// implemented`, `control_plane_store_d1`): a gateway whose keys were all
    /// virtual on D1 -- the hosted-on-Cloudflare posture -- was told at startup
    /// that it had "no credential source" and pointed at `[auth] disabled =
    /// true`, i.e. at switching authentication off. Adding a backend variant now
    /// stops this compiling until the new backend states whether it holds keys.
    pub fn durable_api_key_store(&self) -> Option<StorageProviderKind> {
        let provider = self.storage.provider;
        let holds_durable_api_keys = match provider {
            // Implemented durable control-plane stores: all three resolve a
            // presented key through `find_api_key_records_by_prefix`.
            StorageProviderKind::Postgres
            | StorageProviderKind::Supabase
            | StorageProviderKind::CloudflareD1 => true,
            // In-process only: runtime-minted keys die with the process and
            // nothing outside it can have minted one, so a memory-backed
            // deployment with no static key really has nothing to authenticate
            // against.
            StorageProviderKind::Memory => false,
            // Deliberately excluded because they are not implemented at all
            // (`StorageProviderKind::implemented()` omits both), so there is no
            // control-plane store behind them to hold a key. If either is ever
            // implemented, flip it here -- `credential_sources_cover_every_
            // storage_provider` in `config/tests.rs` cross-checks this list
            // against `implemented()` and reds when it stops being true.
            StorageProviderKind::TursoLibsql | StorageProviderKind::Mysql => false,
        };
        holds_durable_api_keys.then_some(provider)
    }
}

/// Deployment-wide tenant-identity semantics (issue #515).
///
/// `organization_id` is simultaneously (a) the tenant/billing boundary, (b) a
/// foreign key to `tenants.id`, and (c) the *authorization identity* every
/// tenant-isolation check in `crate::auth` reads. Two of its semantics were
/// never written down anywhere an operator could see them, and both defaulted
/// to the permissive answer:
///
/// 1. `organization_id: None` did not mean "no tenant access", it meant
///    **platform root** -- so an *omitted* config field silently minted a
///    credential that reads and mutates every tenant. That is now spelled by
///    [`ApiKey::platform_operator`], and this section decides what happens to a
///    credential that spells neither.
/// 2. an `organization_id` that names no `tenants` row was accepted verbatim on
///    the native/static-config write path -- so a typo silently created a new
///    tenancy island rather than being refused.
///
/// Both flags start in the *legacy* (pre-#515) position so this change is not a
/// silent break for deployments whose env-derived/bootstrap keys are root today
/// (see the migration note on each field); both are logged at load time when a
/// key actually depends on the legacy answer, and both are intended to flip in
/// a subsequent release once operators have written the intent down.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenancyConfig {
    /// DEPRECATED (#515 stage 1). `true` (the legacy default) keeps the
    /// pre-#515 behaviour: an API key that declares neither `organization_id`
    /// nor `platform_operator` is treated as a platform-root credential.
    ///
    /// Set to `false` to fail closed: such a credential is then refused at
    /// authentication with `tenant_identity_required` instead of being promoted
    /// to root, and every key that legitimately administers the whole platform
    /// must say `platform_operator = true` out loud.
    ///
    /// Migration: set `platform_operator = true` on your bootstrap/operator
    /// `[[api_keys]]` entries first (that is accepted under both settings),
    /// then flip this to `false`.
    #[serde(default = "default_true")]
    pub implicit_platform_operator: bool,
    /// `false` (the legacy default) keeps an `organization_id` that resolves to
    /// no `tenants` row acceptable on `POST`/`PUT /admin/v1/api-keys`; the
    /// dangling reference is reported in the gateway log and the admin audit
    /// trail (exactly like an unresolvable `project_id`/`workspace_id`) instead
    /// of being refused.
    ///
    /// `true` makes `organization_id` a checked foreign key on that write path:
    /// naming a tenant that does not exist is a `400`, so a typo can no longer
    /// silently create a tenancy island that no console, quota policy or RBAC
    /// binding will ever match.
    #[serde(default)]
    pub require_registered_tenant: bool,
}

impl Default for TenancyConfig {
    fn default() -> Self {
        Self {
            implicit_platform_operator: true,
            require_registered_tenant: false,
        }
    }
}

/// Time-based agent schedule triggers (#246). The scheduler is a control-plane
/// trigger layer: when a schedule is due it enqueues a dispatch into the
/// existing self-hosted lease queue (or creates an agent run). `enabled =
/// false` (the default) is a complete no-op -- the tick loop is always spawned
/// (like the billing outbox sweeper) but returns immediately when disabled, so
/// turning it on via `/admin/v1/config/reload` needs no restart. Firing is
/// at-most-once per (schedule, slot) with minute-level precision; the tick
/// interval only bounds detection latency.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SchedulerConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Seconds between due-schedule scans. Default 5s -- far below the
    /// minute-level firing contract so a due schedule is picked up promptly.
    #[serde(default = "default_scheduler_tick_interval_secs")]
    pub tick_interval_secs: u64,
    /// Upper bound on catch-up fires processed per schedule in a single tick
    /// after downtime, so a long outage can never replay an unbounded backlog.
    #[serde(default = "default_scheduler_max_catchup_fires")]
    pub max_catchup_fires: u64,
    /// IANA timezone applied to a cron schedule that does not set its own.
    #[serde(default = "default_scheduler_default_timezone")]
    pub default_timezone: String,
}

fn default_scheduler_tick_interval_secs() -> u64 {
    5
}

fn default_scheduler_max_catchup_fires() -> u64 {
    1
}

fn default_scheduler_default_timezone() -> String {
    "UTC".to_string()
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            tick_interval_secs: default_scheduler_tick_interval_secs(),
            max_catchup_fires: default_scheduler_max_catchup_fires(),
            default_timezone: default_scheduler_default_timezone(),
        }
    }
}

/// Asset lifecycle sweeper (issue #263): background version-retention pruning
/// and unreferenced-blob garbage collection. `enabled = false` (the default) is
/// a complete no-op -- the tick loop is always spawned (like the billing outbox
/// and scheduler sweepers) and `sweep_asset_lifecycle_once` re-reads
/// `state.current()`, so enabling it via `/admin/v1/config/reload` needs no
/// restart. Deletion is guarded three ways: `dry_run = true` (the default when
/// enabled) only reports what WOULD be pruned/collected; a channel-pinned or
/// still-within-grace version is never pruned; and GC only deletes a bucket
/// object no `stored_assets` row references, after `gc_grace_secs`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AssetLifecycleConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Seconds between reconcile passes. Default 3600 (hourly) -- lifecycle is
    /// housekeeping, not a hot path.
    #[serde(default = "default_asset_lifecycle_tick_interval_secs")]
    pub tick_interval_secs: u64,
    /// Report-only mode: log/audit what would be pruned or GC'd without
    /// deleting anything. Defaults to `true` so enabling the sweeper is
    /// observably safe until the operator opts into live deletes.
    #[serde(default = "default_asset_lifecycle_dry_run")]
    pub dry_run: bool,
    /// Tenant/plan default: keep the newest N versions of every asset line that
    /// has no more specific `retention_policies` row. `None` disables the
    /// count-based default.
    #[serde(default)]
    pub default_keep_last_n: Option<u64>,
    /// Tenant/plan default max-age (seconds) for versions without a specific
    /// policy. `None` disables the age-based default.
    #[serde(default)]
    pub default_max_age_secs: Option<i64>,
    /// Retention grace window (seconds): never prune a version younger than
    /// this, even when a rule selects it. Default 86400 (1 day).
    #[serde(default = "default_asset_lifecycle_grace_secs")]
    pub retention_min_age_secs: i64,
    /// Whether unreferenced-blob GC runs. Requires a configured `[asset_bucket]`
    /// -- inline-only deployments have no blobs to collect. Default false.
    #[serde(default)]
    pub gc_enabled: bool,
    /// GC grace window (seconds): an unreferenced bucket object younger than
    /// this is kept (it may be an in-flight presigned commit). Default 86400.
    #[serde(default = "default_asset_lifecycle_grace_secs")]
    pub gc_grace_secs: i64,
    /// Upper bound on blob deletes per GC pass so one tick can never issue an
    /// unbounded number of bucket DELETEs. Default 100.
    #[serde(default = "default_asset_lifecycle_max_gc_deletes")]
    pub max_gc_deletes_per_tick: usize,
    /// #284: tenant/plan default max-age (seconds) for `request_logs` rows
    /// without a more specific `retention_policies` row. `None` disables the
    /// request-log TTL default (no pruning unless a tenant policy opts in).
    #[serde(default)]
    pub default_request_log_max_age_secs: Option<i64>,
    /// #284: tenant/plan default max-age (seconds) for `audit_events` rows.
    /// Audit rows carry a LONGER legal floor than request logs, so this is
    /// typically larger (or `None` -- never purge -- while request logs do).
    #[serde(default)]
    pub default_audit_event_max_age_secs: Option<i64>,
    /// #284: shortest default TTL, applied to `request_logs` rows that captured
    /// a response body (`response_recorded`). Data-minimization for the
    /// highest-sensitivity captures; `None` falls back to the request-log
    /// default. A response-body row is pruned as soon as EITHER this or the
    /// general request-log rule selects it.
    #[serde(default)]
    pub default_response_body_max_age_secs: Option<i64>,
    /// #284: upper bound on operational-log row deletes per table per tick, so
    /// one pass can never issue an unbounded DELETE. Default 5000.
    #[serde(default = "default_asset_lifecycle_max_log_deletes")]
    pub max_log_deletes_per_tick: usize,
}

fn default_asset_lifecycle_tick_interval_secs() -> u64 {
    3_600
}

fn default_asset_lifecycle_grace_secs() -> i64 {
    86_400
}

fn default_asset_lifecycle_max_gc_deletes() -> usize {
    100
}

fn default_asset_lifecycle_max_log_deletes() -> usize {
    5_000
}

fn default_asset_lifecycle_dry_run() -> bool {
    true
}

impl Default for AssetLifecycleConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            tick_interval_secs: default_asset_lifecycle_tick_interval_secs(),
            dry_run: true,
            default_keep_last_n: None,
            default_max_age_secs: None,
            retention_min_age_secs: default_asset_lifecycle_grace_secs(),
            gc_enabled: false,
            gc_grace_secs: default_asset_lifecycle_grace_secs(),
            max_gc_deletes_per_tick: default_asset_lifecycle_max_gc_deletes(),
            default_request_log_max_age_secs: None,
            default_audit_event_max_age_secs: None,
            default_response_body_max_age_secs: None,
            max_log_deletes_per_tick: default_asset_lifecycle_max_log_deletes(),
        }
    }
}

/// Background TTL sweeper for overdue x402 payment attempts (issue #354). Each
/// managed paid-egress attempt reserves a wallet hold with a TTL (`hold_ttl_secs`
/// at open time); `X402SettlementLoop::expire_if_due` already knows how to
/// release a *pre-submission* hold once its TTL elapses, but nothing drove it on
/// a schedule, so an attempt that was authorized/challenged but never finalized
/// kept its hold forever. This sweeper fills that gap: on each tick it fetches a
/// bounded batch of due, pre-submission attempts and drives `expire_if_due` for
/// each. `enabled = false` (the default) is a complete no-op -- the tick loop is
/// always spawned (like the billing outbox / scheduler / asset-lifecycle
/// sweepers) and `sweep_x402_expired_attempts_once` re-reads `state.current()`,
/// so enabling it via `/admin/v1/config/reload` needs no restart. It is
/// money-safe by construction: it only ever touches pre-submission holds, and it
/// re-drives the loop's idempotent release edge (never a bespoke transition), so
/// a `submitted` attempt whose stablecoin may have moved on-chain is never
/// released.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct X402SweeperConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Seconds between due-attempt scans. Default 30s -- holds are minute-scale,
    /// and expiry is housekeeping, not a hot path.
    #[serde(default = "default_x402_sweeper_tick_interval_secs")]
    pub tick_interval_secs: u64,
    /// Upper bound on attempts expired per tick, so one pass can never issue an
    /// unbounded number of releases / table scan. Default 100.
    #[serde(default = "default_x402_sweeper_max_expiries_per_tick")]
    pub max_expiries_per_tick: usize,
    /// Extra grace (seconds) added to a hold's TTL before the sweeper considers
    /// it due: an attempt is swept only once `hold_expires_at + grace <= now`.
    /// A defensive delay so the sweeper never races a hold that only just
    /// elapsed while an in-flight finalize is still landing. Default 0 (expire
    /// exactly at the hold's own TTL, matching `expire_if_due`).
    #[serde(default)]
    pub hold_ttl_grace_secs: i64,
}

fn default_x402_sweeper_tick_interval_secs() -> u64 {
    30
}

fn default_x402_sweeper_max_expiries_per_tick() -> usize {
    100
}

impl Default for X402SweeperConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            tick_interval_secs: default_x402_sweeper_tick_interval_secs(),
            max_expiries_per_tick: default_x402_sweeper_max_expiries_per_tick(),
            hold_ttl_grace_secs: 0,
        }
    }
}

/// Background on-chain settlement reconciler for x402 payment attempts (issue
/// #354). The TTL sweeper deliberately leaves `submitted`/`outcome_unknown`
/// attempts alone -- after proof submission an attempt's stablecoin may already
/// have moved on-chain, so releasing its hold could spend without charging the
/// wallet. This reconciler is the loop that resolves exactly those left-behind
/// attempts: on each tick it fetches a bounded batch of post-submission attempts
/// due for a re-check, queries an injected on-chain-RPC seam for each attempt's
/// transaction signature, and applies an EXPLICIT trust order:
///
/// - a confirmed on-chain transfer of the EXACT owed amount -> SETTLE (capture
///   the hold, attempt -> settled);
/// - a transfer the chain definitively rejected, or one still absent PAST
///   `confirmation_deadline_secs` since submission -> FAIL (release the hold,
///   attempt -> failed);
/// - anything still pending/ambiguous, or an amount MISMATCH -> remain
///   `outcome_unknown` (hold RETAINED), advancing the backoff cursor. NEVER a
///   guess.
///
/// On-chain RPC evidence is authoritative over any merchant-reported header.
/// `enabled = false` (the default) is a complete no-op -- the tick loop is
/// always spawned (like the sweeper) and re-reads `state.current()`, so enabling
/// it via `/admin/v1/config/reload` needs no restart. Reuses the settlement
/// loop's existing SETTLE/FAIL/UNKNOWN edges (idempotent under the CAS
/// `generation` token), so it is money-safe to run on every gateway instance
/// concurrently.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct X402ReconcilerConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Seconds between reconcile scans. Default 30s -- settlement latency is
    /// second-to-minute scale; reconciliation is housekeeping, not a hot path.
    #[serde(default = "default_x402_reconciler_tick_interval_secs")]
    pub tick_interval_secs: u64,
    /// Upper bound on attempts reconciled per tick, so one pass can never issue
    /// an unbounded number of on-chain RPC queries / edge drives. Default 100.
    #[serde(default = "default_x402_reconciler_max_reconciles_per_tick")]
    pub max_reconciles_per_tick: usize,
    /// Minimum age (seconds) since an attempt's last state update before it is
    /// eligible for an on-chain re-check: an attempt is reconciled only once
    /// `updated_at_unix + reconcile_check_delay_secs <= now`. This both gives a
    /// freshly-submitted proof time to propagate before the first check AND is
    /// the bounded-backoff interval -- re-parking a still-pending attempt bumps
    /// `updated_at_unix`, deferring its next check by this delay. Default 60s.
    #[serde(default = "default_x402_reconciler_check_delay_secs")]
    pub reconcile_check_delay_secs: i64,
    /// Confirmation deadline (seconds since `submitted_at_unix`) after which a
    /// transfer the chain reports ABSENT (never landed) is treated as a definite
    /// FAIL and its hold released. Before the deadline, an absent signature stays
    /// `outcome_unknown` (it may still be propagating). A transfer the chain
    /// reports as definitively rejected fails immediately regardless of this
    /// deadline; a pending (seen but unconfirmed) transfer NEVER fails on this
    /// deadline (its money may still confirm). Default 900s (15 min).
    #[serde(default = "default_x402_reconciler_confirmation_deadline_secs")]
    pub confirmation_deadline_secs: i64,
    /// Operator-declared TTL (seconds) of the wallet hold a paid-egress attempt
    /// reserves at settlement-open time (`X402SettlementLoop::open` sets the
    /// hold's `expires_at = opened_at + hold_ttl_secs`). This exists here so the
    /// money-safety invariant below can be enforced at config load (issue #400):
    /// the wallet primitive REFUSES to capture (settle) a hold past its TTL and
    /// auto-releases it, so if the hold expires before the reconciler can capture
    /// a payment that IS confirmed on-chain, the stablecoin is delivered but the
    /// wallet is never charged -- a silent money loss. `validate()` therefore
    /// rejects (when `enabled = true`) any config where `hold_ttl_secs` does not
    /// strictly outlive the window `confirmation_deadline_secs` plus
    /// `reconcile_check_delay_secs` plus one reconciler tick of slack. Default
    /// 3600s (1h), which comfortably outlives the default 900+60+30 = 990s window.
    ///
    /// NOTE: the settlement open path currently receives the hold TTL as a
    /// call-site runtime parameter (`X402NegotiationContext.hold_ttl_secs`); the
    /// egress-path wiring that sources it FROM this field is remaining work
    /// (issue #401 box 1, blocked on #381), tracked alongside the deferred
    /// capture-past-TTL wallet change on #400. Until that lands, the per-request
    /// value cannot BYPASS this invariant: `X402SettlementLoop::open` clamps
    /// every requested TTL up to [`x402_hold_ttl_floor_secs`], the same floor
    /// `validate()` enforces here (issue #401 box 3).
    #[serde(default = "default_x402_reconciler_hold_ttl_secs")]
    pub hold_ttl_secs: i64,
}

/// The settlement confirmation window (seconds) a wallet hold must survive:
/// `confirmation_deadline_secs + reconcile_check_delay_secs + one reconciler
/// tick of slack` (issue #400).
///
/// The reconciler only resolves a `submitted` attempt after it has queried the
/// chain: an attempt is not eligible for a re-check until
/// `reconcile_check_delay_secs` have elapsed, an absent transfer is not declared
/// FAIL until `confirmation_deadline_secs` after submission, and the reconciler
/// scans on a `tick_interval_secs` cadence so it may take one more tick to
/// notice a now-due attempt.
///
/// Saturating throughout: an operator-supplied `u64` tick larger than `i64::MAX`
/// (or component sums that overflow) must produce an absurdly LARGE window --
/// which rejects/clamps conservatively -- never a wrapped small one.
pub fn x402_confirmation_window_secs(reconciler: &X402ReconcilerConfig) -> i64 {
    let slack_secs = i64::try_from(reconciler.tick_interval_secs).unwrap_or(i64::MAX);
    reconciler
        .confirmation_deadline_secs
        .saturating_add(reconciler.reconcile_check_delay_secs)
        .saturating_add(slack_secs)
}

/// THE single definition of the money-safety floor for an x402 wallet hold TTL
/// (issues #400, #401): the smallest TTL that STRICTLY outlives
/// [`x402_confirmation_window_secs`], i.e. `window + 1`.
///
/// Two callers, one definition, so they can never drift:
/// 1. `Config::validate_x402_reconciler` rejects any config whose
///    `x402_reconciler.hold_ttl_secs` is below this floor (issue #400);
/// 2. `X402SettlementLoop::open` clamps every PER-REQUEST hold TTL up to this
///    floor, so the runtime parameter cannot bypass (1) (issue #401).
///
/// A hold shorter than this can auto-release before the reconciler is able to
/// capture a payment that IS confirmed on-chain: the stablecoin is delivered but
/// the wallet is never charged.
pub fn x402_hold_ttl_floor_secs(reconciler: &X402ReconcilerConfig) -> i64 {
    x402_confirmation_window_secs(reconciler).saturating_add(1)
}

fn default_x402_reconciler_tick_interval_secs() -> u64 {
    30
}

fn default_x402_reconciler_max_reconciles_per_tick() -> usize {
    100
}

fn default_x402_reconciler_check_delay_secs() -> i64 {
    60
}

fn default_x402_reconciler_confirmation_deadline_secs() -> i64 {
    900
}

fn default_x402_reconciler_hold_ttl_secs() -> i64 {
    3600
}

impl Default for X402ReconcilerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            tick_interval_secs: default_x402_reconciler_tick_interval_secs(),
            max_reconciles_per_tick: default_x402_reconciler_max_reconciles_per_tick(),
            reconcile_check_delay_secs: default_x402_reconciler_check_delay_secs(),
            confirmation_deadline_secs: default_x402_reconciler_confirmation_deadline_secs(),
            hold_ttl_secs: default_x402_reconciler_hold_ttl_secs(),
        }
    }
}

/// S3-compatible object-storage bucket for `/v1/assets/*` content (issue
/// #176). Optional and additive: `enabled = false` (the default) keeps
/// every asset's bytes inline in `stored_assets.content`, the original
/// #176 design -- unset entirely, this whole feature is a no-op. Supabase
/// Storage exposes an S3-compatible endpoint using the same SigV4 auth
/// scheme AWS S3 does, so this also works against a real AWS S3 bucket or
/// any other S3-compatible service (MinIO, etc.), not only Supabase.
/// Which object-storage backend `[asset_bucket]` drives (issue #411). The
/// default `s3` covers every S3-compatible service (AWS S3, Supabase Storage,
/// MinIO, Cloudflare R2) through the one SigV4 client. `workers-static-assets`
/// selects a Cloudflare-native publish backend that is NOT S3-shaped and is
/// wired through the shared [`ferrogate_cloudflare::CloudflareClient`] instead;
/// it uses the `cf_*` fields below rather than the S3 credential pieces.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssetBucketBackend {
    /// The S3-compatible SigV4 backend (AWS S3 / Supabase / MinIO / R2). The
    /// historical and default behavior — unchanged by #411.
    #[default]
    S3,
    /// Cloudflare Workers Static Assets direct-upload publish backend (#411).
    WorkersStaticAssets,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AssetBucketConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Selects the object-storage backend (issue #411). Defaults to the
    /// S3-compatible client, so existing `[asset_bucket]` configs are
    /// unchanged.
    #[serde(default)]
    pub backend: AssetBucketBackend,
    /// `scheme://host[:port]`, no trailing slash, no bucket/key suffix --
    /// e.g. `https://<project>.supabase.co/storage/v1/s3`.
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub bucket: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    /// Not a secret itself -- paired with `secret_access_key_env` for the
    /// actual secret, mirroring `Provider::aws_access_key_id`'s split.
    #[serde(default)]
    pub access_key_id: Option<String>,
    #[serde(default)]
    pub secret_access_key_env: Option<String>,
    /// TTL (seconds) for gateway-issued presigned upload/download URLs
    /// (issue #259). Bounded to S3's 7-day maximum and defaulted to 15
    /// minutes when unset -- short-lived by design so a leaked URL expires
    /// quickly.
    #[serde(default)]
    pub presign_ttl_secs: Option<u64>,
    /// Per-object size ceiling (bytes) for the presigned large-file path
    /// (issue #259). Independent of the cumulative, tenant-wide
    /// `asset_storage_quota_bytes` cap. Defaults to 5 GiB when unset.
    #[serde(default)]
    pub presign_max_object_bytes: Option<u64>,
    /// The largest object the gateway will ever hold in memory for an asset
    /// operation (issue #259). Objects at or below it keep the buffered,
    /// full-fidelity path (whole-file signature verification, out-of-process
    /// malware scanning, `mcp_manifest` transport parsing). Larger objects are
    /// verified and copied in a single bounded-memory streaming pass at commit
    /// time, and are pulled through the presigned direct-download endpoint
    /// rather than the gateway hot path. Defaults to
    /// `INLINE_ASSET_MAX_BYTES` (10 MiB) when unset, so an inline-stored asset
    /// is never affected. Raising it re-enables whole-file controls for larger
    /// objects at a proportional, explicitly-accepted memory cost.
    #[serde(default)]
    pub max_gateway_buffer_bytes: Option<u64>,
    /// The aggregate ceiling (bytes) on everything the gateway is holding for
    /// buffering, bucket-backed reads at one instant (issue #529).
    ///
    /// `max_gateway_buffer_bytes` bounds ONE operation; this bounds their sum,
    /// which is what an operator actually sizes a box from. A read holds its
    /// charge until its bytes are dropped; when the budget is committed a read
    /// waits at most
    /// `buffer_admission_wait_ms` and is then refused with a typed
    /// `503 gateway_buffer_budget_exhausted` -- never truncated, never queued
    /// indefinitely.
    ///
    /// WHAT A READ IS CHARGED is not always the object size. A read that only
    /// buffers -- the REST pull, static-site serve, the buffered commit leg --
    /// is charged the size its registry row declares. A read whose bytes are
    /// INLINED INTO A JSON RESPONSE (`fetch_asset`, MCP `resources/read`) is
    /// charged roughly 3.7x that: the buffer, the base64 copy, and the
    /// serialized body are all resident at the peak. Charging those surfaces
    /// the object size alone is what made the ceiling untrue for them before
    /// the #529 rework -- the budget was honest about admission and wrong
    /// about residency. See `docs/assets/private-bucket-migration.md` for the
    /// per-surface table.
    ///
    /// Unset defaults to `32 x max_gateway_buffer_bytes` (320 MiB at the
    /// defaults), which is above any concurrency a healthy box reaches, so an
    /// unconfigured deployment is bounded without changing what it serves.
    /// `0` disables admission control entirely, restoring the pre-#529
    /// unbounded behavior; it never means "admit nothing". A value below
    /// `max_gateway_buffer_bytes` is raised to it, since a budget that cannot
    /// admit one legal read is a deadlock, not a limit.
    #[serde(default)]
    pub max_total_gateway_buffer_bytes: Option<u64>,
    /// How long (milliseconds) a buffering read waits for aggregate budget
    /// before it is shed (issue #529). Unset defaults to 250 ms -- long enough
    /// to absorb the sub-second overlap of a burst, short enough that the shed
    /// is a fast answer rather than something a caller experiences as a hang.
    /// `0` sheds immediately with no queueing.
    #[serde(default)]
    pub buffer_admission_wait_ms: Option<u64>,
    /// Cloudflare account id for the `workers-static-assets` backend (#411).
    /// Ignored by the default S3 backend.
    #[serde(default)]
    pub cf_account_id: Option<String>,
    /// Cloudflare API token *reference* for the `workers-static-assets`
    /// backend (#411) — an `env://VAR` reference or an inline token, resolved
    /// via [`ferrogate_cloudflare::EnvTokenResolver`]. Ignored by the S3
    /// backend.
    #[serde(default)]
    pub cf_api_token: Option<String>,
    /// The Worker script name the uploaded static assets attach to for the
    /// `workers-static-assets` backend (#411). Ignored by the S3 backend.
    #[serde(default)]
    pub cf_script_name: Option<String>,
}

impl AssetBucketConfig {
    /// Whether the runtime will actually construct the S3/R2 SigV4 client for
    /// this section (issue #485).
    ///
    /// `AppState::asset_bucket_client` returns `None` for a disabled section
    /// and for the Cloudflare-native backend, so the S3-only load-time guards
    /// (`validate_asset_bucket`'s credential-presence rules and the R2 host /
    /// region rules) must key off exactly the same condition -- otherwise a
    /// section carrying leftover S3 fields hard-fails config load for a client
    /// that is never built. Both the runtime accessor and the validators call
    /// this so the condition cannot drift.
    pub fn builds_s3_client(&self) -> bool {
        self.enabled && matches!(self.backend, AssetBucketBackend::S3)
    }
}

/// Pre-authentication network controls (issue #166), applied to every
/// request before virtual-key/storage lookups. All fields are additive and
/// default to the pre-#166 behavior (no allowlist, no pre-auth throttling).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct NetworkAccessConfig {
    /// CIDR ranges (or bare IPs) allowed to reach the gateway. Empty means
    /// "no restriction" — every source IP is allowed, matching prior
    /// behavior.
    #[serde(default)]
    pub ip_allowlist: Vec<String>,
    /// Whether to trust `X-Forwarded-For`/`X-Real-IP` over the raw TCP peer
    /// address when resolving the client IP for allowlist/rate-limit
    /// decisions. Only enable this when FerroGate sits behind trusted reverse
    /// proxies and is reachable only through them — otherwise any client can
    /// spoof its apparent source IP. Defaults to `false` (trust only the raw
    /// peer address).
    #[serde(default)]
    pub trust_forwarded_for: bool,
    /// Number of trusted reverse proxies in front of the gateway. When
    /// `trust_forwarded_for` is set, the client IP is taken this many entries
    /// from the RIGHT of `X-Forwarded-For` (each trusted proxy appends exactly
    /// one entry), so client-supplied leftmost entries cannot spoof the source
    /// IP. Defaults to `1` (a single fronting load balancer) when trusting
    /// forwarded headers; set higher for a chain of N proxies.
    #[serde(default)]
    pub trusted_proxy_hops: Option<u32>,
    /// Maximum requests per source IP per minute before authentication is
    /// even attempted. `None` (the default) disables pre-auth throttling.
    #[serde(default)]
    pub unauthenticated_rate_limit_per_minute: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AdminConfig {
    #[serde(default)]
    pub listen: Option<String>,
    /// Origin reflected back as `Access-Control-Allow-Origin` on every
    /// locally-handled admin API response (including an `OPTIONS` preflight),
    /// so a separately-deployed admin console frontend can call `/admin/v1/*`
    /// cross-origin without an Ingress/reverse-proxy CORS layer in front.
    /// Unset disables CORS headers entirely. Applied once at process start;
    /// changing it requires a restart (not picked up by `/admin/v1/config/reload`).
    #[serde(default)]
    pub cors_allowed_origin: Option<String>,
}

/// `[control_api]` (canonical; deprecated alias `[admin_api]`) -- the
/// standalone FerroGate Control Plane API service (issue #359, formerly the
/// #315 admin-api; `ferrogate control-api serve`). A dedicated listener that
/// terminates the console's HTTP(S), authenticates the caller with the
/// gateway's own admin-scope semantics, and reverse-proxies the
/// path-compatible `/admin/v1/*` (+ `/v1/assets/*`) surface to the gateway
/// over `gateway_url`, so control-plane traffic never rides the AI
/// data-plane listener.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct AdminApiConfig {
    /// Address the Control Plane API service listens on.
    #[serde(default = "default_admin_api_listen")]
    pub listen: String,
    /// Internal base URL of the running gateway the admin surface is
    /// proxied to. `http://` only: this is a private service-to-service
    /// hop (same trust posture as `auth_service.endpoint` /
    /// `billing_service.endpoint`); terminate public TLS on this
    /// service's own listener via `tls_cert_path`/`tls_key_path` or at an
    /// Ingress in front of it.
    #[serde(default = "default_admin_api_gateway_url")]
    pub gateway_url: String,
    /// Per-attempt connect/read/write timeout for the proxied hop.
    #[serde(default = "default_admin_api_upstream_timeout_millis")]
    pub upstream_timeout_millis: u64,
    /// Origin reflected as `Access-Control-Allow-Origin` on locally
    /// generated responses (the OPTIONS preflight and auth-gate errors);
    /// proxied responses carry the gateway's own CORS headers, so set the
    /// gateway's `admin.cors_allowed_origin` to the same origin.
    #[serde(default)]
    pub cors_allowed_origin: Option<String>,
    /// Optional TLS for the admin-api listener (PEM certificate chain +
    /// private key). Both must be set together; unset serves plain HTTP.
    #[serde(default)]
    pub tls_cert_path: Option<String>,
    #[serde(default)]
    pub tls_key_path: Option<String>,
}

impl Default for AdminApiConfig {
    fn default() -> Self {
        Self {
            listen: default_admin_api_listen(),
            gateway_url: default_admin_api_gateway_url(),
            upstream_timeout_millis: default_admin_api_upstream_timeout_millis(),
            cors_allowed_origin: None,
            tls_cert_path: None,
            tls_key_path: None,
        }
    }
}

fn default_admin_api_listen() -> String {
    "127.0.0.1:8095".to_string()
}

fn default_admin_api_gateway_url() -> String {
    "http://127.0.0.1:8080".to_string()
}

fn default_admin_api_upstream_timeout_millis() -> u64 {
    30_000
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct AuthServiceConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_auth_service_endpoint")]
    pub endpoint: String,
    #[serde(default = "default_auth_service_timeout_millis")]
    pub timeout_millis: u64,
    #[serde(default)]
    pub max_retries: u32,
    #[serde(default = "default_auth_service_retry_backoff_millis")]
    pub retry_backoff_millis: u64,
}

/// Gateway-side client config for the standalone billing service (issue #131).
/// When `enabled`, the gateway reports each settled usage event to the billing
/// service's `POST /v1/billing/charge` over REST (fire-and-forget, so the hot
/// path is never blocked on the billing round-trip).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct BillingServiceConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_billing_service_endpoint")]
    pub endpoint: String,
    #[serde(default = "default_billing_service_timeout_millis")]
    pub timeout_millis: u64,
    /// Optional service-to-service bearer token sent to the billing service.
    #[serde(default)]
    pub token: Option<String>,
    /// Optional env var name holding the billing service bearer token.
    #[serde(default)]
    pub token_env: Option<String>,
}

impl Default for BillingServiceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_billing_service_endpoint(),
            timeout_millis: default_billing_service_timeout_millis(),
            token: None,
            token_env: None,
        }
    }
}

fn default_billing_service_endpoint() -> String {
    "http://127.0.0.1:8092".to_string()
}

fn default_billing_service_timeout_millis() -> u64 {
    1_000
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ClusterConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_cluster_id")]
    pub cluster_id: String,
    #[serde(default = "default_cluster_node_id")]
    pub node_id: String,
    #[serde(default)]
    pub node_region: Option<String>,
    #[serde(default)]
    pub node_zone: Option<String>,
    #[serde(default = "default_cluster_state_backend")]
    pub state_backend: String,
    #[serde(default)]
    pub file_state_path: Option<String>,
    #[serde(default = "default_cluster_counter_backend")]
    pub counter_backend: String,
    #[serde(default)]
    pub redis_url: Option<String>,
    #[serde(default = "default_cluster_counter_timeout_millis")]
    pub counter_timeout_millis: u64,
    #[serde(default = "default_cluster_heartbeat_interval_secs")]
    pub heartbeat_interval_secs: u64,
    #[serde(default = "default_cluster_config_poll_interval_secs")]
    pub config_poll_interval_secs: u64,
    /// Ed25519 signing key (base64 standard, 32-byte seed) THIS node uses to
    /// sign the file-backed control-plane snapshots it publishes. When set,
    /// `publish_from_config` embeds a signed envelope in the snapshot; when
    /// unset, snapshots are published unsigned (legacy behavior). Issue #206.
    #[serde(default)]
    pub snapshot_signing_key: Option<String>,
    /// Key id advertised in signed snapshots this node publishes; peers look it
    /// up in their `snapshot_trusted_keys`. Required when `snapshot_signing_key`
    /// is set.
    #[serde(default)]
    pub snapshot_signing_key_id: Option<String>,
    /// Trusted Ed25519 verifying keys (key_id -> base64 standard 32-byte public
    /// key). When non-empty, a loaded file-backed snapshot MUST carry a valid
    /// signature from one of these keys (matching identity + a strictly newer
    /// revision + unexpired) before it is activated; a snapshot that fails
    /// verification is rejected and the running config (last known good) is
    /// retained. Empty = verification disabled (legacy behavior).
    #[serde(default)]
    pub snapshot_trusted_keys: Vec<ClusterSnapshotKey>,
    /// Tenant identity the snapshot signature must bind to. Required when
    /// signing or verification is enabled.
    #[serde(default)]
    pub snapshot_tenant_id: Option<String>,
    /// Deployment identity the snapshot signature must bind to. Required when
    /// signing or verification is enabled.
    #[serde(default)]
    pub snapshot_deployment_id: Option<String>,
    /// TTL (seconds) applied to signed snapshots this node publishes:
    /// `not_after_unix = now + this`. Peers reject a snapshot once expired.
    #[serde(default = "default_cluster_snapshot_max_age_secs")]
    pub snapshot_max_age_secs: u64,
}

/// A trusted Ed25519 verifying key for signed control-plane snapshots (#206).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ClusterSnapshotKey {
    pub key_id: String,
    /// Base64 (standard alphabet) of the 32-byte Ed25519 public key.
    pub public_key: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct AgentRuntimeConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub provider: AgentRuntimeProvider,
    #[serde(default = "default_agent_runtime_max_turns")]
    pub max_turns: u32,
    #[serde(default = "default_agent_runtime_timeout_millis")]
    pub timeout_millis: u64,
    #[serde(default)]
    pub external: AgentRuntimeExternalConfig,
    #[serde(default)]
    pub managed_worker: AgentRuntimeManagedWorkerConfig,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentRuntimeProvider {
    #[default]
    ManagedWorker,
    External,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct AgentRuntimeExternalConfig {
    #[serde(default)]
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub timeout_millis: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct AgentRuntimeManagedWorkerConfig {
    #[serde(default)]
    pub external_action_authorizer_http_listen: Option<String>,
    #[serde(default)]
    pub external_action_authorizer_socket: Option<String>,
    #[serde(default)]
    pub external_action_authorizer_max_requests: Option<usize>,
    #[serde(default)]
    pub allowed_actions: Vec<ManagedWorkerCapabilityActionConfig>,
    #[serde(default)]
    pub approval_required_actions: Vec<ManagedWorkerCapabilityActionConfig>,
    #[serde(default)]
    pub allow_direct_network_egress: bool,
    #[serde(default)]
    pub target_grants: Vec<ManagedWorkerCapabilityTargetGrantConfig>,
    #[serde(default)]
    pub class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode,
    #[serde(default = "default_managed_worker_policy_revision")]
    pub policy_revision: String,
}

impl Default for AgentRuntimeManagedWorkerConfig {
    fn default() -> Self {
        Self {
            external_action_authorizer_http_listen: None,
            external_action_authorizer_socket: None,
            external_action_authorizer_max_requests: None,
            allowed_actions: Vec::new(),
            approval_required_actions: Vec::new(),
            allow_direct_network_egress: false,
            target_grants: Vec::new(),
            class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::Deny,
            policy_revision: default_managed_worker_policy_revision(),
        }
    }
}

fn default_managed_worker_policy_revision() -> String {
    "config-v1".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ManagedWorkerCapabilityTargetGrantConfig {
    pub selector_id: String,
    pub permission_key: String,
    pub action: ManagedWorkerCapabilityActionConfig,
    pub selector: ferrogate_runtime::CapabilityTargetSelector,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ManagedWorkerCapabilityActionConfig {
    Tool,
    McpTool,
    Cli,
    Skill,
    Filesystem,
    Browser,
    Rest,
    Secret,
    MemoryRead,
    MemoryWrite,
    NetworkEgress,
}

impl ManagedWorkerCapabilityActionConfig {
    pub fn as_str(self) -> &'static str {
        self.as_policy_action().as_str()
    }

    pub fn as_policy_action(self) -> ferrogate_runtime::CapabilityAction {
        match self {
            Self::Tool => ferrogate_runtime::CapabilityAction::Tool,
            Self::McpTool => ferrogate_runtime::CapabilityAction::McpTool,
            Self::Cli => ferrogate_runtime::CapabilityAction::Cli,
            Self::Skill => ferrogate_runtime::CapabilityAction::Skill,
            Self::Filesystem => ferrogate_runtime::CapabilityAction::Filesystem,
            Self::Browser => ferrogate_runtime::CapabilityAction::Browser,
            Self::Rest => ferrogate_runtime::CapabilityAction::Rest,
            Self::Secret => ferrogate_runtime::CapabilityAction::Secret,
            Self::MemoryRead => ferrogate_runtime::CapabilityAction::MemoryRead,
            Self::MemoryWrite => ferrogate_runtime::CapabilityAction::MemoryWrite,
            Self::NetworkEgress => ferrogate_runtime::CapabilityAction::NetworkEgress,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct TlsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub cert_path: Option<String>,
    #[serde(default)]
    pub key_path: Option<String>,
    #[serde(default)]
    pub http2: bool,
    #[serde(default)]
    pub acme: TlsAcmeConfig,
}

impl TlsConfig {
    pub fn is_enabled(&self) -> bool {
        self.enabled || self.cert_path.is_some() || self.key_path.is_some() || self.acme.enabled
    }

    pub fn manual_cert_and_key(&self) -> Option<(&str, &str)> {
        Some((self.cert_path.as_deref()?, self.key_path.as_deref()?))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct TlsAcmeConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default = "default_acme_directory_url")]
    pub directory_url: String,
    #[serde(default = "default_acme_challenge")]
    pub challenge: String,
    #[serde(default = "default_http_challenge_listen")]
    pub http_challenge_listen: String,
    #[serde(default = "default_acme_storage_dir")]
    pub storage_dir: String,
    #[serde(default)]
    pub terms_agreed: bool,
    #[serde(default)]
    pub dns_provider: Option<String>,
    #[serde(default)]
    pub dns_config: BTreeMap<String, String>,
    #[serde(default)]
    pub dns_hook_set: Option<String>,
    #[serde(default)]
    pub dns_hook_cleanup: Option<String>,
    #[serde(default = "default_dns_propagation_delay_secs")]
    pub dns_propagation_delay_secs: u64,
    #[serde(default = "default_acme_renewal_window_secs")]
    pub renewal_window_secs: u64,
    #[serde(default = "default_acme_renewal_check_interval_secs")]
    pub renewal_check_interval_secs: u64,
    #[serde(default = "default_acme_renewal_retry_interval_secs")]
    pub renewal_retry_interval_secs: u64,
    #[serde(default = "default_true")]
    pub auto_graceful_reload: bool,
}

impl Default for TlsAcmeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            domains: Vec::new(),
            email: None,
            directory_url: default_acme_directory_url(),
            challenge: default_acme_challenge(),
            http_challenge_listen: default_http_challenge_listen(),
            storage_dir: default_acme_storage_dir(),
            terms_agreed: false,
            dns_provider: None,
            dns_config: BTreeMap::new(),
            dns_hook_set: None,
            dns_hook_cleanup: None,
            dns_propagation_delay_secs: default_dns_propagation_delay_secs(),
            renewal_window_secs: default_acme_renewal_window_secs(),
            renewal_check_interval_secs: default_acme_renewal_check_interval_secs(),
            renewal_retry_interval_secs: default_acme_renewal_retry_interval_secs(),
            auto_graceful_reload: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Provider {
    pub name: String,
    #[serde(default = "default_provider_kind")]
    pub kind: String,
    pub base_url: String,
    #[serde(default)]
    pub api_key_env: Option<String>,
    /// Secret-manager reference (`env://NAME` or `vault://mount/path#field`,
    /// issue #163), resolved once at config load/reload time and cached —
    /// see `AppState::resolved_provider_secrets`. Takes precedence over
    /// `api_key_env` when both are set and resolution succeeds.
    #[serde(default)]
    pub secret_ref: Option<String>,
    #[serde(default)]
    pub openrouter_http_referer: Option<String>,
    #[serde(default)]
    pub openrouter_x_title: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Physical region this provider is hosted in (issue #173), e.g.
    /// "eu-west-1" -- additive and `#[serde(default)]` so existing configs
    /// deserialize unchanged. Enforced against a tenant's region
    /// allowlist (`ApiKey::region_allowlist`) at routing time via
    /// `AppState::candidate_model_routes`; unset means the provider isn't
    /// eligible for a region-constrained tenant (fails closed, not open).
    #[serde(default)]
    pub region: Option<String>,
    /// AWS access key id for the `bedrock` provider kind (issue #172) --
    /// not a secret itself (safe to store in plain config), paired with
    /// `aws_secret_access_key_env` for the actual secret. `region` above
    /// (already used for #173's data-residency routing) doubles as the
    /// AWS region a Bedrock provider targets, rather than adding a
    /// duplicate field.
    #[serde(default)]
    pub aws_access_key_id: Option<String>,
    /// Environment variable holding the AWS secret access key. This
    /// resolves AWS credentials from the environment only (not through
    /// the vault-backed `secret_ref` mechanism `api_key_env` has), since
    /// Bedrock needs two independent secrets (secret key + optional
    /// session token) rather than the single generic `api_key` that
    /// mechanism was built for -- a deliberate scope-narrowing for
    /// issue #172's first cut, not a design dead-end.
    #[serde(default)]
    pub aws_secret_access_key_env: Option<String>,
    /// Environment variable holding a temporary AWS session token (STS
    /// assumed-role credentials). Omit for long-lived IAM user access
    /// keys.
    #[serde(default)]
    pub aws_session_token_env: Option<String>,
    /// GCP project id for the `vertex` provider kind (issue #172). Like
    /// `aws_access_key_id`, not a secret -- safe to store in plain
    /// config. `region` above doubles as the GCP location (e.g.
    /// `us-central1`) a Vertex AI provider targets, the same reuse
    /// `aws_access_key_id`'s doc comment already established for AWS.
    #[serde(default)]
    pub gcp_project_id: Option<String>,
    /// Environment variable holding a pre-minted GCP OAuth2 access token
    /// (scope `cloud-platform`). FerroGate does not mint or refresh this
    /// token itself -- see `GcpProviderCredentials`'s doc comment in
    /// `ferrogate-providers` for why -- so it must be kept fresh by an
    /// external process (e.g. a `gcloud auth application-default
    /// print-access-token` cron, or an ADC-aware sidecar).
    #[serde(default)]
    pub gcp_access_token_env: Option<String>,
    /// Per-provider Cloudflare AI Gateway routing (issue #406). When set (and
    /// a top-level `[cloudflare]` block is configured, issue #405), the
    /// provider's already-prepared upstream request is rewritten onto the
    /// tenant's Cloudflare AI Gateway (see
    /// `ferrogate_providers::CloudflareAiGatewayRouting`). Absent (the
    /// `#[serde(default)]` case) = direct dispatch, unchanged and non-breaking.
    /// `account_id` and the gateway/api base URLs come from `[cloudflare]`, so
    /// they are never repeated here.
    #[serde(default)]
    pub cloudflare_ai_gateway: Option<ProviderCloudflareAiGatewayConfig>,
}

/// Per-provider Cloudflare AI Gateway routing block (issue #406).
///
/// Opt-in: absent means the provider dispatches directly, exactly as before.
/// `account_id` and the gateway/api base URLs are taken from the top-level
/// `[cloudflare]` block (issue #405), never repeated here; only the
/// per-provider gateway id, the optional AI-Gateway auth-token reference, the
/// surface mode, and an optional Cloudflare provider-slug override live here.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProviderCloudflareAiGatewayConfig {
    /// AI Gateway id (the `{gateway_id}` path segment / `cf-aig-gateway-id`
    /// header). Required.
    pub gateway_id: String,
    /// Optional secret reference (`env://…`, `vault://…`, or `cf://…`) for the
    /// AI Gateway auth token, resolved through the same secret path as a
    /// provider key. Absent/empty = an unauthenticated gateway (no
    /// `cf-aig-authorization` header injected).
    #[serde(default)]
    pub aig_token_secret_ref: Option<String>,
    /// Which Cloudflare surface to route through. Defaults to `compat`.
    #[serde(default)]
    pub mode: ProviderCloudflareAiGatewayMode,
    /// Explicit Cloudflare provider-slug override (the path segment in compat
    /// mode / the `author` prefix in unified mode). Absent = derived from the
    /// provider family (`openai`/`anthropic`).
    #[serde(default)]
    pub provider_slug: Option<String>,
}

/// The Cloudflare AI Gateway surface a provider routes through -- the
/// serde-aware file-config mirror of
/// `ferrogate_providers::CloudflareAiGatewayMode` (which is not
/// `Deserialize`/`Serialize`). Converted to the runtime enum in
/// `state_routing.rs`.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCloudflareAiGatewayMode {
    /// Per-provider passthrough surface. Default -- forwards the provider
    /// request shape verbatim.
    #[default]
    Compat,
    /// Unified REST API surface (`author/model` body form, gateway selected via
    /// header).
    Unified,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Model {
    /// Logical model name exposed by FerroGate clients.
    pub name: String,
    /// Provider name from [[providers]].
    pub provider: String,
    /// Actual model name sent to the upstream provider.
    pub provider_model: String,
    #[serde(default)]
    pub routing_strategy: RoutingStrategy,
    #[serde(default)]
    pub fallbacks: Vec<ModelFallback>,
    /// Canary rollout (issue #276): route a deterministic, sticky
    /// percentage of this logical model's traffic to an alternate
    /// provider/model. Sticky by api key / tenant so a given caller lands
    /// consistently on (or off) the canary. When selected the canary simply
    /// becomes the leading candidate, so it is evaluated exactly like the
    /// primary route -- fully governed, billed, and guarded -- and falls
    /// back to the primary on failure. Absent = no canary (behavior
    /// unchanged); `percent = 100` promotes the canary to primary as a
    /// config-only change.
    #[serde(default)]
    pub canary: Option<CanaryRoute>,
    /// Shadow/mirror rollout (issue #276): duplicate a sampled,
    /// budget-capped fraction of this model's requests to a secondary
    /// provider/model without affecting the client response. Fire-and-forget
    /// (adds no client latency); metered as shadow (never billed to the
    /// tenant, never trips the primary provider's circuit breaker). Absent =
    /// no shadow.
    #[serde(default)]
    pub shadow: Option<ShadowRoute>,
    #[serde(default)]
    pub visible_organization_ids: Vec<String>,
    #[serde(default)]
    pub visible_project_ids: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub context_window: Option<u32>,
    #[serde(default)]
    pub input_price_per_1m: Option<f64>,
    #[serde(default)]
    pub output_price_per_1m: Option<f64>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub cache_enabled: Option<bool>,
}

/// Canary target for a logical model (issue #276).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CanaryRoute {
    /// Provider name from `[[providers]]` to canary onto.
    pub provider: String,
    /// Actual model name sent to the canary provider.
    pub provider_model: String,
    /// Percentage of traffic (0-100) routed to the canary. `0` disables the
    /// split (no canary traffic); `100` sends all traffic to the canary
    /// (canary becomes primary).
    #[serde(default)]
    pub percent: u8,
    #[serde(default)]
    pub input_price_per_1m: Option<f64>,
    #[serde(default)]
    pub output_price_per_1m: Option<f64>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// Shadow/mirror target for a logical model (issue #276).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ShadowRoute {
    /// Provider name from `[[providers]]` to mirror requests to.
    pub provider: String,
    /// Actual model name sent to the shadow provider.
    pub provider_model: String,
    /// Percentage of requests (0-100) mirrored to the shadow target,
    /// sampled stickily by api key / tenant. `0` disables mirroring.
    #[serde(default)]
    pub sample_percent: u8,
    /// Maximum shadow dispatches admitted per process lifetime (across all
    /// callers of this model); `0` = uncapped. Caps the mirror's cost.
    #[serde(default)]
    pub max_requests: u64,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ModelFallback {
    pub provider: String,
    pub provider_model: String,
    #[serde(default)]
    pub input_price_per_1m: Option<f64>,
    #[serde(default)]
    pub output_price_per_1m: Option<f64>,
    #[serde(default)]
    pub priority: Option<u32>,
    #[serde(default)]
    pub weight: Option<u32>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiKey {
    /// Stable non-secret identifier used in logs and audit records.
    pub id: String,
    pub name: String,
    /// Environment variable containing the secret value. Preferred for real use.
    #[serde(default)]
    pub key_env: Option<String>,
    /// Plain value for local development only. Do not use in production.
    #[serde(default)]
    pub key: Option<String>,
    /// Hashed key value for durable config. Use `ferrogate hash-key --secret ...` to generate.
    #[serde(default)]
    pub key_hash: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub allowed_models: Vec<String>,
    #[serde(default)]
    pub denied_models: Vec<String>,
    #[serde(default)]
    pub allowed_providers: Vec<String>,
    #[serde(default)]
    pub denied_providers: Vec<String>,
    /// Regions this key's requests may route to (issue #173), e.g.
    /// ["eu-west-1"] -- empty means unrestricted, mirroring
    /// `allowed_models`/`allowed_providers`. Enforced in
    /// `AppState::candidate_model_routes` against each `ModelRoute`'s
    /// `region` (sourced from `Provider::region`); a route with no
    /// declared region is ineligible once this is non-empty (fail closed,
    /// not open).
    #[serde(default)]
    pub region_allowlist: Vec<String>,
    /// The tenant this credential speaks for: a foreign key to `tenants.id`,
    /// and the authorization identity every tenant-isolation check in
    /// `crate::auth` reads (`authorize_tenant_scope`, `filter_by_tenant_scope`,
    /// `enforce_tenant_filter`, ...). It is NOT free-form attribution: a value
    /// that names no tenant scopes the key to a tenancy island that no console,
    /// quota policy or RBAC binding will ever match, and `[tenancy]
    /// require_registered_tenant = true` refuses it outright on the admin write
    /// path (issue #515).
    ///
    /// Absent means "this key names no tenant" -- which is only a legitimate
    /// shape for a platform operator, and one that must now say so via
    /// [`Self::platform_operator`].
    #[serde(default)]
    pub organization_id: Option<String>,
    /// Explicit platform-root opt-in (issue #515). `Some(true)` grants the
    /// unrestricted, cross-tenant identity that `organization_id: None` used to
    /// confer implicitly; it is mutually exclusive with `organization_id`
    /// (rejected at load) because root is the absence of a tenant, not a
    /// tenant.
    ///
    /// `Some(false)` is an explicit refusal of root. Combined with an
    /// `organization_id` it is redundant but harmless (a key that names a
    /// tenant is never root anyway); combined with NO `organization_id` it
    /// leaves the key with no tenant identity at all, and such a credential is
    /// refused at authentication (`tenant_identity_required`) rather than
    /// served -- `organization_id` is also the attribution key for quota,
    /// metering and lifecycle, so an identity-less credential is wrong on the
    /// data plane too, not just on admin routes.
    ///
    /// `None` (field omitted) is resolved by
    /// [`super::TenancyConfig::implicit_platform_operator`]: root under the
    /// legacy default, refused at authentication once that is flipped off.
    #[serde(default)]
    pub platform_operator: Option<bool>,
    #[serde(default)]
    pub team_id: Option<String>,
    #[serde(default)]
    pub project_id: Option<String>,
    #[serde(default)]
    pub workspace_id: Option<String>,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub monthly_token_budget: Option<u64>,
    #[serde(default)]
    pub request_limit_per_minute: Option<u64>,
    #[serde(default)]
    pub expires_at_unix: Option<u64>,
    #[serde(default)]
    pub log_bodies: Option<bool>,
    #[serde(default)]
    pub cache_enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyRule {
    pub name: String,
    #[serde(default = "default_policy_effect")]
    pub effect: String,
    #[serde(default)]
    pub organization_ids: Vec<String>,
    #[serde(default)]
    pub project_ids: Vec<String>,
    #[serde(default)]
    pub api_key_ids: Vec<String>,
    #[serde(default)]
    pub models: Vec<String>,
    #[serde(default)]
    pub providers: Vec<String>,
    #[serde(default = "default_policy_code")]
    pub code: String,
    #[serde(default = "default_policy_message")]
    pub message: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfigProfile {
    pub id: String,
    pub name: String,
    #[serde(default = "default_gateway_config_revision")]
    pub revision: u32,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub api_key_ids: Vec<String>,
    #[serde(default)]
    pub cache_enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AgentWorkflowPolicy {
    pub id: String,
    pub name: String,
    #[serde(default = "default_gateway_config_revision")]
    pub version: u32,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub organization_ids: Vec<String>,
    #[serde(default)]
    pub project_ids: Vec<String>,
    #[serde(default)]
    pub api_key_ids: Vec<String>,
    pub nodes: Vec<AgentWorkflowNode>,
    #[serde(default)]
    pub edges: Vec<AgentWorkflowEdge>,
    #[serde(default)]
    pub max_model_calls: Option<u32>,
    #[serde(default)]
    pub max_tool_calls: Option<u32>,
    #[serde(default)]
    pub max_parallelism: Option<u32>,
    #[serde(default)]
    pub max_iterations: Option<u32>,
    #[serde(default)]
    pub timeout_millis: Option<u64>,
    #[serde(default)]
    pub token_budget: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AgentWorkflowNode {
    pub id: String,
    #[serde(default)]
    pub kind: AgentWorkflowNodeKind,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub providers: Vec<String>,
    #[serde(default)]
    pub tool: Option<String>,
    #[serde(default)]
    pub max_iterations: Option<u32>,
    #[serde(default)]
    pub token_budget: Option<u64>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentWorkflowNodeKind {
    #[default]
    Model,
    Tool,
    Router,
    Human,
    Checkpoint,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AgentWorkflowEdge {
    pub from: String,
    pub to: String,
    #[serde(default)]
    pub condition: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PromptTemplate {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub status: PromptTemplateStatus,
    #[serde(default)]
    pub target: PromptTemplateTarget,
    pub model: String,
    #[serde(default)]
    pub variables: Vec<PromptTemplateVariable>,
    pub versions: Vec<PromptTemplateVersion>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PromptTemplateStatus {
    Draft,
    #[default]
    Active,
    Archived,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PromptTemplateTarget {
    #[default]
    ChatCompletions,
    Responses,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PromptTemplateVariable {
    pub name: String,
    #[serde(default = "default_true")]
    pub required: bool,
    #[serde(default)]
    pub default: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PromptTemplateVersion {
    #[serde(default = "default_gateway_config_revision")]
    pub revision: u32,
    #[serde(default)]
    pub status: PromptTemplateVersionStatus,
    pub messages: Vec<PromptTemplateMessage>,
    #[serde(default)]
    pub temperature: Option<f64>,
    #[serde(default)]
    pub top_p: Option<f64>,
    #[serde(default)]
    pub max_tokens: Option<u32>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PromptTemplateVersionStatus {
    Draft,
    #[default]
    Active,
    Archived,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PromptTemplateMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GuardrailRule {
    pub id: String,
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_guardrail_stage")]
    pub stage: GuardrailStage,
    #[serde(default = "all_content_sources")]
    pub sources: Vec<ContentSource>,
    #[serde(default)]
    pub organization_ids: Vec<String>,
    #[serde(default)]
    pub project_ids: Vec<String>,
    #[serde(default)]
    pub api_key_ids: Vec<String>,
    #[serde(default)]
    pub models: Vec<String>,
    #[serde(default)]
    pub providers: Vec<String>,
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default)]
    pub regex: Vec<String>,
    #[serde(default)]
    pub max_input_bytes: Option<usize>,
    #[serde(default)]
    pub provider: GuardrailProviderKind,
    #[serde(default)]
    pub provider_endpoint: Option<String>,
    /// Presidio only: language hint sent with every analyze request.
    #[serde(default)]
    pub provider_language: Option<String>,
    /// Presidio / LLM-Guard only: minimum score to act on, percent (0-100).
    #[serde(default)]
    pub provider_score_threshold_percent: Option<u8>,
    /// Presidio only: optional recognizer entity allow-list.
    #[serde(default)]
    pub provider_entities: Option<Vec<String>>,
    /// Presidio / LLM-Guard: required secret reference used to key evidence
    /// fingerprints (HMAC over the flagged content).
    #[serde(default)]
    pub provider_fingerprint_secret_ref: Option<String>,
    #[serde(default = "default_guardrail_provider_timeout_ms")]
    pub provider_timeout_ms: u64,
    #[serde(flatten)]
    pub provider_runtime: GuardrailProviderRuntimeConfig,
    #[serde(default = "default_guardrail_effect")]
    pub effect: GuardrailEffect,
    #[serde(default = "default_guardrail_code")]
    pub code: String,
    #[serde(default = "default_guardrail_message")]
    pub message: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GuardrailProviderRuntimeConfig {
    #[serde(default)]
    pub provider_on_error: GuardrailProviderErrorMode,
    #[serde(default = "default_guardrail_provider_max_concurrency")]
    pub provider_max_concurrency: usize,
    #[serde(default = "default_guardrail_provider_circuit_failure_threshold")]
    pub provider_circuit_failure_threshold: u32,
    #[serde(default = "default_guardrail_provider_circuit_cooldown_ms")]
    pub provider_circuit_cooldown_ms: u64,
    #[serde(default)]
    pub provider_max_retries: u8,
    #[serde(default = "default_guardrail_provider_max_payload_bytes")]
    pub provider_max_payload_bytes: usize,
    #[serde(default = "default_guardrail_provider_max_response_bytes")]
    pub provider_max_response_bytes: usize,
    #[serde(default)]
    pub provider_allow_private_network: bool,
    #[serde(default)]
    pub provider_secret_ref: Option<String>,
}

impl Default for GuardrailProviderRuntimeConfig {
    fn default() -> Self {
        Self {
            provider_on_error: GuardrailProviderErrorMode::Block,
            provider_max_concurrency: default_guardrail_provider_max_concurrency(),
            provider_circuit_failure_threshold:
                default_guardrail_provider_circuit_failure_threshold(),
            provider_circuit_cooldown_ms: default_guardrail_provider_circuit_cooldown_ms(),
            provider_max_retries: 0,
            provider_max_payload_bytes: default_guardrail_provider_max_payload_bytes(),
            provider_max_response_bytes: default_guardrail_provider_max_response_bytes(),
            provider_allow_private_network: false,
            provider_secret_ref: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GuardrailProviderErrorMode {
    #[default]
    Block,
    Record,
    FallbackDetector,
}

/// Selects how a [`GuardrailRule`] decides whether text matches: in-process
/// keyword/regex/length checks (`None`, the default) or delegation to an
/// external detector reachable over HTTP — a generic `CustomHttp` endpoint,
/// or one of the native self-hosted semantic adapters (#201): `Presidio`
/// (Microsoft Presidio analyzer, DLP/PII with span redaction) and
/// `LlmGuardPromptInjection` (ProtectAI LLM-Guard prompt scanner,
/// detect-only). The native adapters require
/// `provider_fingerprint_secret_ref` for keyed evidence.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GuardrailProviderKind {
    #[default]
    None,
    CustomHttp,
    Presidio,
    LlmGuardPromptInjection,
}

impl GuardrailProviderKind {
    /// True for every kind that dispatches to an external HTTP detector.
    pub fn is_external(self) -> bool {
        !matches!(self, Self::None)
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GuardrailStage {
    #[default]
    Request,
    Response,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GuardrailEffect {
    #[default]
    Deny,
    Redact,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionKind {
    RequestHook,
    ToolProvider,
    EventSink,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ExtensionConfig {
    pub id: String,
    pub kind: ExtensionKind,
    #[serde(default = "default_plugin_manifest_version")]
    pub version: String,
    #[serde(default)]
    pub manifest: PluginManifest,
    #[serde(default)]
    pub compatibility: PluginCompatibility,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_extension_source")]
    pub source: String,
    #[serde(default = "default_extension_order")]
    pub order: u32,
    #[serde(default)]
    pub approval_policy: ApprovalPolicy,
    #[serde(default)]
    pub permissions: ExtensionPermissions,
    #[serde(default)]
    pub config: BTreeMap<String, toml::Value>,
}

pub type PluginConfig = ExtensionConfig;

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
pub struct PluginManifest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub required_permissions: ExtensionPermissions,
    #[serde(default)]
    pub hooks: Vec<String>,
    #[serde(default)]
    pub config_schema: Option<toml::Value>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PluginCompatibility {
    #[serde(default)]
    pub min_gateway_version: Option<String>,
    #[serde(default)]
    pub max_gateway_version: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
pub struct SkillPackage {
    pub id: String,
    pub name: String,
    #[serde(default = "default_skill_package_version")]
    pub version: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub compatibility: SkillPackageCompatibility,
    #[serde(default)]
    pub permissions: ExtensionPermissions,
    #[serde(default)]
    pub capabilities: Vec<SkillPackageCapability>,
    #[serde(default)]
    pub resources: SkillPackageResources,
    #[serde(default)]
    pub api_key_ids: Vec<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, toml::Value>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
pub struct SkillPackageResources {
    #[serde(default)]
    pub plugins: Vec<PluginConfig>,
    #[serde(default)]
    pub mcp_servers: Vec<McpServerConfig>,
    #[serde(default)]
    pub prompt_templates: Vec<PromptTemplate>,
    #[serde(default)]
    pub agent_workflows: Vec<AgentWorkflowPolicy>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct SkillPackageCompatibility {
    #[serde(default)]
    pub min_gateway_version: Option<String>,
    #[serde(default)]
    pub agent_runtimes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct SkillPackageCapability {
    pub kind: SkillPackageCapabilityKind,
    pub id: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SkillPackageCapabilityKind {
    Plugin,
    Tool,
    McpServer,
    McpTool,
    PromptTemplate,
    AgentWorkflow,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
pub struct ExtensionPermissions {
    #[serde(default)]
    pub tools: Vec<String>,
    #[serde(default)]
    pub network: Vec<String>,
    #[serde(default)]
    pub filesystem: bool,
    #[serde(default)]
    pub shell: bool,
    #[serde(default)]
    pub tenant_scope: bool,
    #[serde(default)]
    pub secrets: bool,
    #[serde(default)]
    pub admin_mutation: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TelemetryConfig {
    #[serde(default = "default_service_name")]
    pub service_name: String,
    #[serde(default)]
    pub log_bodies: bool,
    #[serde(default)]
    pub access_log: AccessLogMode,
    #[serde(default = "default_access_log_sample_rate")]
    pub access_log_sample_rate: u64,
    #[serde(default = "default_access_log_error_rate_limit_per_sec")]
    pub access_log_error_rate_limit_per_sec: u64,
    #[serde(default)]
    pub otlp_endpoint: Option<String>,
}

/// Outbound notification channel for proactive budget-threshold alerting
/// (issue #170) -- fired once per `StoredQuotaPolicy::alert_threshold_pcts`
/// tier per scope per billing period, strictly before the unconditional
/// `monthly_budget_exceeded` 429 hard-deny at 100%. Webhook is the only
/// channel implemented today; `webhook_url` is the documented extension
/// point other channels (email/Slack) would plug into alongside.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BillingAlertsConfig {
    /// POST target for budget-threshold-crossing notifications. `None`
    /// (the default) disables dispatch entirely -- threshold crossings are
    /// still detected and recorded (so a later-configured webhook doesn't
    /// replay history), just not delivered anywhere.
    #[serde(default)]
    pub webhook_url: Option<String>,
    #[serde(default = "default_billing_alerts_webhook_timeout_secs")]
    pub webhook_timeout_secs: u64,
    /// HMAC-SHA256 secret for signing budget-alert webhooks (issue #228). When
    /// set, each delivery carries `X-FerroGate-Timestamp` and
    /// `X-FerroGate-Signature: sha256=<hex of HMAC(secret, "<timestamp>.<body>")>`
    /// so a receiver can authenticate the alert and reject replays; `None`
    /// leaves alerts unsigned (legacy). Prefer an env placeholder so the secret
    /// is not stored in plaintext config.
    #[serde(default)]
    pub webhook_signing_secret: Option<String>,
}

fn default_billing_alerts_webhook_timeout_secs() -> u64 {
    5
}

impl Default for BillingAlertsConfig {
    fn default() -> Self {
        Self {
            webhook_url: None,
            webhook_timeout_secs: default_billing_alerts_webhook_timeout_secs(),
            webhook_signing_secret: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ObservabilityConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub provider: ObservabilityProvider,
    /// OTLP/HTTP+JSON collector endpoint. Under
    /// [`ObservabilityProvider::Cloudflare`] this is the URL of the FerroGate
    /// `telemetry-collector` Worker (issue #520) rather than a self-hosted
    /// collector; the wire protocol is identical either way.
    #[serde(default)]
    pub otlp_endpoint: Option<String>,
    /// Secret reference (`env://NAME`, `cf://...`, ...) for the bearer token
    /// the Cloudflare collector Worker requires. Resolved through the shared
    /// `SecretResolverRegistry` seam so the credential is never plaintext in
    /// this file (issue #520).
    #[serde(default)]
    pub cloudflare_collector_token_ref: Option<String>,
    /// Fallback tenant for telemetry records that carry no tenant attribute.
    /// Analytics Engine allows exactly one `index` per data point and the
    /// collector uses the tenant as that index, so it needs some value.
    #[serde(default)]
    pub cloudflare_default_tenant: Option<String>,
    #[serde(default = "default_observability_prometheus_metrics_path")]
    pub prometheus_metrics_path: String,
    #[serde(default = "default_observability_export_timeout_secs")]
    pub export_timeout_secs: u64,
    /// #357: running-presence TTL (seconds) for the observed-agent-activity
    /// surface. A virtual API key whose most recent observed request is within
    /// this window is reported `running`; older evidence expires to `inactive`.
    /// Default 60. An operator can raise/lower it here or, without editing the
    /// config, via the `FERROGATE_OBSERVED_ACTIVITY_RUNNING_TTL_SECONDS` env
    /// override (see `resolve_observed_activity_running_ttl_seconds`).
    #[serde(default = "default_observability_observed_activity_running_ttl_secs")]
    pub observed_activity_running_ttl_secs: u64,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ObservabilityProvider {
    #[default]
    Vector,
    Otlp,
    /// Cloudflare-native observability via the FerroGate `telemetry-collector`
    /// Worker, which fans out to Analytics Engine + Workers Logs (issue #520).
    /// Cloudflare exposes no telemetry ingest endpoint of its own, so the
    /// Worker we deploy *is* the ingest endpoint.
    Cloudflare,
    None,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AnalyticsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub provider: AnalyticsProvider,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub vector_endpoint: Option<String>,
    #[serde(default)]
    pub clickhouse_url: Option<String>,
    #[serde(default)]
    pub clickhouse_url_env: Option<String>,
    #[serde(default = "default_analytics_export_timeout_secs")]
    pub export_timeout_secs: u64,
    #[serde(default = "default_analytics_batch_max_events")]
    pub batch_max_events: usize,
    #[serde(default = "default_analytics_flush_interval_millis")]
    pub flush_interval_millis: u64,
    #[serde(default = "default_analytics_queue_capacity")]
    pub queue_capacity: usize,
    #[serde(default = "default_request_log_retention_records")]
    pub request_log_retention_records: usize,
    #[serde(default = "default_audit_event_retention_records")]
    pub audit_event_retention_records: usize,
    #[serde(default = "default_guardrail_evaluation_retention_records")]
    pub guardrail_evaluation_retention_records: usize,
    #[serde(default = "default_billing_event_retention_records")]
    pub billing_event_retention_records: usize,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AnalyticsProvider {
    #[default]
    Vector,
    Clickhouse,
    None,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MeteringConfig {
    #[serde(default)]
    pub export_enabled: bool,
    #[serde(default)]
    pub export_provider: MeteringExportProvider,
    #[serde(default = "default_metering_export_endpoint")]
    pub export_endpoint: String,
    #[serde(default)]
    pub export_token_env: Option<String>,
    #[serde(default)]
    pub export_token: Option<String>,
    #[serde(default = "default_metering_export_timeout_secs")]
    pub export_timeout_secs: u64,
    #[serde(default = "default_metering_export_event_type")]
    pub export_event_type: String,
    #[serde(default = "default_metering_export_source")]
    pub export_source: String,
    #[serde(default)]
    pub export_subject: MeteringExportSubject,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MeteringExportProvider {
    #[default]
    Legacy,
    Openmeter,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MeteringExportSubject {
    #[default]
    #[serde(rename = "api_key_id")]
    ApiKey,
    #[serde(rename = "organization_id")]
    Organization,
    #[serde(rename = "project_id")]
    Project,
    #[serde(rename = "user_id")]
    User,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CacheConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub mode: CacheMode,
    #[serde(default = "default_cache_ttl_secs")]
    pub ttl_secs: u64,
    #[serde(default = "default_cache_max_records")]
    pub max_records: usize,
    /// Cosine-similarity threshold for `CacheMode::Semantic` (#273). A prior
    /// cached response is served only when the current request's prompt
    /// embedding is within this cosine distance of the stored one. Ignored
    /// unless `mode = "semantic"`. Range (0.0, 1.0].
    #[serde(default = "default_cache_semantic_similarity_threshold")]
    pub semantic_similarity_threshold: f32,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CacheMode {
    #[default]
    ExactMatch,
    /// Embedding-based similarity lookup (#273): on an exact-match miss, the
    /// gateway embeds the request prompt and serves a prior cached response
    /// whose stored embedding is within `semantic_similarity_threshold`.
    /// Behind the same cache seam — same tenant scoping and guardrail-policy
    /// invalidation as exact-match.
    Semantic,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccessLogMode {
    Off,
    #[default]
    Error,
    Sampled,
    All,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StorageConfig {
    #[serde(default)]
    pub provider: StorageProviderKind,
    #[serde(default)]
    pub required: bool,
    #[serde(default = "default_storage_provider_order")]
    pub provider_order: Vec<StorageProviderKind>,
    #[serde(default)]
    pub libsql_url: Option<String>,
    #[serde(default)]
    pub libsql_auth_token: Option<String>,
    #[serde(default)]
    pub libsql_auth_token_env: Option<String>,
    #[serde(default)]
    pub postgres_dsn: Option<String>,
    #[serde(default)]
    pub postgres_dsn_env: Option<String>,
    #[serde(default)]
    pub supabase_dsn_env: Option<String>,
    #[serde(default = "default_postgres_pool_size")]
    pub postgres_pool_size: usize,
    #[serde(default = "default_postgres_pool_acquire_timeout_millis")]
    pub postgres_pool_acquire_timeout_millis: u64,
    #[serde(default)]
    pub postgres_tls_mode: PostgresTlsMode,
    #[serde(default)]
    pub postgres_tls_ca_cert_path: Option<String>,
    #[serde(default = "default_postgres_connect_timeout_secs")]
    pub postgres_connect_timeout_secs: u64,
    #[serde(default = "default_postgres_statement_timeout_millis")]
    pub postgres_statement_timeout_millis: u64,
    #[serde(default)]
    pub postgres_schema: Option<String>,
    #[serde(default)]
    pub postgres_search_path: Vec<String>,
    /// D1 control-database uuid for `provider = "cloudflare_d1"` (issue #445):
    /// the database holding `tenants`, config documents, and the account-global
    /// families. Absent/empty means "not provisioned yet" -- the backend rejects
    /// control-plane access until `provision_control_database` seeds it.
    #[serde(default)]
    pub d1_control_database_id: Option<String>,
    /// Pre-seeded `tenant_id -> D1 database uuid` registry entries (issue #445),
    /// for a deployment resuming against already-provisioned tenant databases.
    #[serde(default)]
    pub d1_tenant_databases: std::collections::BTreeMap<String, String>,
    #[serde(default = "default_storage_migration_mode")]
    pub migration_mode: StorageMigrationMode,
    #[serde(default = "default_admin_list_limit")]
    pub admin_list_default_limit: usize,
    #[serde(default = "default_admin_list_max_limit")]
    pub admin_list_max_limit: usize,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StorageMigrationMode {
    #[default]
    Auto,
    ValidateOnly,
    Disabled,
}

impl StorageMigrationMode {
    pub fn as_str(self) -> &'static str {
        match self {
            StorageMigrationMode::Auto => "auto",
            StorageMigrationMode::ValidateOnly => "validate_only",
            StorageMigrationMode::Disabled => "disabled",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReliabilityConfig {
    #[serde(default)]
    pub provider_circuit_breaker_failure_threshold: Option<u32>,
    #[serde(default)]
    pub provider_circuit_breaker_cooldown_secs: Option<u64>,
    #[serde(default)]
    pub provider_dispatch_timeout_secs: Option<u64>,
    #[serde(default)]
    pub provider_dispatch_max_retries: Option<u32>,
    #[serde(default)]
    pub provider_response_body_max_bytes: Option<usize>,
    #[serde(default = "default_tool_approval_timeout_secs")]
    pub tool_approval_timeout_secs: u64,
    #[serde(default = "default_mcp_dispatch_timeout_secs")]
    pub mcp_dispatch_timeout_secs: u64,
    #[serde(default = "default_mcp_dispatch_max_concurrency")]
    pub mcp_dispatch_max_concurrency: usize,
    #[serde(default)]
    pub graceful_shutdown_grace_period_secs: Option<u64>,
    #[serde(default)]
    pub graceful_shutdown_timeout_secs: Option<u64>,
    #[serde(default)]
    pub graceful_upgrade_pid_file: Option<String>,
    #[serde(default)]
    pub graceful_upgrade_sock: Option<String>,
    #[serde(default)]
    pub graceful_upgrade_sock_retries: Option<usize>,
}

/// #312: centralized request-body size caps (`[limits]`).
///
/// Every `read_request_body` call site in the gateway resolves its cap
/// through this section instead of a scattered hard-coded literal. Each
/// knob groups handlers that shared the same literal and purpose before
/// centralization; the defaults below are exactly those literals, so an
/// absent `[limits]` section leaves behavior unchanged.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct LimitsConfig {
    /// `/v1/chat/completions`, `/v1/embeddings`, `/v1/images/generations`,
    /// `/v1/messages` request bodies. Default 1 MiB.
    #[serde(default)]
    pub inference_body_max_bytes: Option<usize>,
    /// Standard `/admin/v1/*` JSON mutations (providers/models/api-keys/
    /// policies/plugins/prompt-templates/skill-packages/agent-workflows/
    /// agent-upstreams/mcp-servers/gateway-configs upserts, plans, quota
    /// policies, RBAC, virtual keys/tenants, agent schedules, admin
    /// agent-run mutations, self-hosted worker management). Default 64 KiB.
    #[serde(default)]
    pub admin_body_max_bytes: Option<usize>,
    /// Compact admin control operations: wallet mutations, site-domain
    /// bindings, `/admin/v1/drain`, tool-approval decisions. Default 16 KiB.
    #[serde(default)]
    pub admin_small_body_max_bytes: Option<usize>,
    /// Full-config documents posted to `/admin/v1/config/validate` and
    /// `/admin/v1/config/reload`. Default 256 KiB.
    #[serde(default)]
    pub admin_config_body_max_bytes: Option<usize>,
    /// Data-plane tool/agent invocation payloads: `/v1/tools/execute`,
    /// `/v1/mcp/tool/execute`, `/v1/functions/execute`, `/v1/mcp` JSON-RPC,
    /// `/v1/prompts/{id}/render`, `/v1/agent-runs` creation. Default 64 KiB.
    #[serde(default)]
    pub tool_body_max_bytes: Option<usize>,
    /// Asset control-plane JSON (`/v1/assets/presign/*` upload-intent,
    /// commit, download-url requests) -- not asset payload bytes themselves,
    /// which are governed by tenant storage quotas. Default 64 KiB.
    #[serde(default)]
    pub asset_control_body_max_bytes: Option<usize>,
    /// A2A agent ingress bodies on `/v1/agents/*`. Default 128 KiB.
    #[serde(default)]
    pub agent_ingress_body_max_bytes: Option<usize>,
    /// Self-hosted worker transport frames (lease poll/ack, heartbeat,
    /// checkpoint, artifact, telemetry envelopes). Default 1 MiB.
    #[serde(default)]
    pub worker_transport_body_max_bytes: Option<usize>,
    /// `/admin/v1/guardrail-policies` documents, which can carry large
    /// pattern lists. Default 1 MiB.
    #[serde(default)]
    pub guardrail_policy_body_max_bytes: Option<usize>,
}

pub const DEFAULT_INFERENCE_BODY_MAX_BYTES: usize = 1024 * 1024;
pub const DEFAULT_ADMIN_BODY_MAX_BYTES: usize = 64 * 1024;
pub const DEFAULT_ADMIN_SMALL_BODY_MAX_BYTES: usize = 16 * 1024;
pub const DEFAULT_ADMIN_CONFIG_BODY_MAX_BYTES: usize = 256 * 1024;
pub const DEFAULT_TOOL_BODY_MAX_BYTES: usize = 64 * 1024;
pub const DEFAULT_ASSET_CONTROL_BODY_MAX_BYTES: usize = 64 * 1024;
pub const DEFAULT_AGENT_INGRESS_BODY_MAX_BYTES: usize = 128 * 1024;
pub const DEFAULT_WORKER_TRANSPORT_BODY_MAX_BYTES: usize = 1024 * 1024;
pub const DEFAULT_GUARDRAIL_POLICY_BODY_MAX_BYTES: usize = 1024 * 1024;

impl LimitsConfig {
    pub fn inference_body_max_bytes(&self) -> usize {
        self.inference_body_max_bytes
            .unwrap_or(DEFAULT_INFERENCE_BODY_MAX_BYTES)
    }

    pub fn admin_body_max_bytes(&self) -> usize {
        self.admin_body_max_bytes
            .unwrap_or(DEFAULT_ADMIN_BODY_MAX_BYTES)
    }

    pub fn admin_small_body_max_bytes(&self) -> usize {
        self.admin_small_body_max_bytes
            .unwrap_or(DEFAULT_ADMIN_SMALL_BODY_MAX_BYTES)
    }

    pub fn admin_config_body_max_bytes(&self) -> usize {
        self.admin_config_body_max_bytes
            .unwrap_or(DEFAULT_ADMIN_CONFIG_BODY_MAX_BYTES)
    }

    pub fn tool_body_max_bytes(&self) -> usize {
        self.tool_body_max_bytes
            .unwrap_or(DEFAULT_TOOL_BODY_MAX_BYTES)
    }

    pub fn asset_control_body_max_bytes(&self) -> usize {
        self.asset_control_body_max_bytes
            .unwrap_or(DEFAULT_ASSET_CONTROL_BODY_MAX_BYTES)
    }

    pub fn agent_ingress_body_max_bytes(&self) -> usize {
        self.agent_ingress_body_max_bytes
            .unwrap_or(DEFAULT_AGENT_INGRESS_BODY_MAX_BYTES)
    }

    pub fn worker_transport_body_max_bytes(&self) -> usize {
        self.worker_transport_body_max_bytes
            .unwrap_or(DEFAULT_WORKER_TRANSPORT_BODY_MAX_BYTES)
    }

    pub fn guardrail_policy_body_max_bytes(&self) -> usize {
        self.guardrail_policy_body_max_bytes
            .unwrap_or(DEFAULT_GUARDRAIL_POLICY_BODY_MAX_BYTES)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Upstream {
    pub name: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct AgentUpstreamConfig {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_agent_upstream_protocol")]
    pub protocol: AgentUpstreamProtocol,
    pub endpoint: String,
    #[serde(default)]
    pub auth: AgentUpstreamAuth,
    #[serde(default)]
    pub tenant_ids: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<AgentUpstreamCapability>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentUpstreamProtocol {
    #[default]
    A2a,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentUpstreamAuth {
    #[default]
    None,
    Bearer {
        token: Option<String>,
    },
    Header {
        name: String,
        value: Option<String>,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentUpstreamCapability {
    Invoke,
    Read,
    Stream,
    Discover,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RouteRule {
    pub name: String,
    pub upstream: String,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub path_prefixes: Vec<String>,
    #[serde(default)]
    pub match_headers: Vec<HeaderMatcher>,
    #[serde(default)]
    pub strip_prefix: Option<String>,
    #[serde(default)]
    pub add_prefix: Option<String>,
    #[serde(default)]
    pub request_headers: Vec<HeaderMutation>,
    #[serde(default)]
    pub response_headers: Vec<HeaderMutation>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HeaderMutation {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HeaderMatcher {
    pub name: String,
    pub value: String,
}

fn default_listen() -> String {
    "127.0.0.1:8080".to_string()
}

fn default_auth_service_endpoint() -> String {
    "http://127.0.0.1:8090".to_string()
}

fn default_auth_service_timeout_millis() -> u64 {
    500
}

fn default_auth_service_retry_backoff_millis() -> u64 {
    50
}

fn default_provider_kind() -> String {
    "openai".to_string()
}

fn default_service_name() -> String {
    "ferrogate".to_string()
}

fn default_true() -> bool {
    true
}

fn default_agent_upstream_protocol() -> AgentUpstreamProtocol {
    AgentUpstreamProtocol::A2a
}

fn default_cluster_id() -> String {
    "default".to_string()
}

fn default_cluster_node_id() -> String {
    "auto".to_string()
}

fn default_cluster_state_backend() -> String {
    "local".to_string()
}

fn default_cluster_counter_backend() -> String {
    "local".to_string()
}

fn default_cluster_counter_timeout_millis() -> u64 {
    500
}

fn default_cluster_heartbeat_interval_secs() -> u64 {
    10
}

fn default_cluster_config_poll_interval_secs() -> u64 {
    5
}

fn default_cluster_snapshot_max_age_secs() -> u64 {
    3_600
}

fn default_agent_runtime_max_turns() -> u32 {
    4
}

fn default_agent_runtime_timeout_millis() -> u64 {
    30_000
}

fn default_skill_package_version() -> String {
    "0.1.0".into()
}

fn default_acme_directory_url() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".to_string()
}

fn default_acme_challenge() -> String {
    "dns-01".to_string()
}

fn default_http_challenge_listen() -> String {
    "0.0.0.0:80".to_string()
}

fn default_acme_storage_dir() -> String {
    ".ferrogate/acme".to_string()
}

fn default_dns_propagation_delay_secs() -> u64 {
    30
}

fn default_acme_renewal_window_secs() -> u64 {
    30 * 24 * 60 * 60
}

fn default_acme_renewal_check_interval_secs() -> u64 {
    12 * 60 * 60
}

fn default_acme_renewal_retry_interval_secs() -> u64 {
    30 * 60
}

fn default_policy_effect() -> String {
    "deny".to_string()
}

fn default_policy_code() -> String {
    "policy_denied".to_string()
}

fn default_policy_message() -> String {
    "request denied by policy".to_string()
}

fn default_gateway_config_revision() -> u32 {
    1
}

fn default_guardrail_stage() -> GuardrailStage {
    GuardrailStage::Request
}

fn default_guardrail_effect() -> GuardrailEffect {
    GuardrailEffect::Deny
}

fn default_guardrail_code() -> String {
    "guardrail_denied".to_string()
}

fn default_guardrail_message() -> String {
    "request blocked by guardrail".to_string()
}

fn default_guardrail_provider_timeout_ms() -> u64 {
    2_000
}

fn default_guardrail_provider_max_concurrency() -> usize {
    16
}

fn default_guardrail_provider_circuit_failure_threshold() -> u32 {
    3
}

fn default_guardrail_provider_circuit_cooldown_ms() -> u64 {
    30_000
}

fn default_guardrail_provider_max_payload_bytes() -> usize {
    1024 * 1024
}

fn default_guardrail_provider_max_response_bytes() -> usize {
    256 * 1024
}

fn default_extension_source() -> String {
    "builtin".to_string()
}

fn default_extension_order() -> u32 {
    100
}

fn default_plugin_manifest_version() -> String {
    "0.1.0".to_string()
}

fn default_access_log_sample_rate() -> u64 {
    100
}

fn default_access_log_error_rate_limit_per_sec() -> u64 {
    100
}

fn default_metering_export_endpoint() -> String {
    "https://api.token4ai.cloud/v1/metering/events".to_string()
}

fn default_metering_export_timeout_secs() -> u64 {
    3
}

fn default_metering_export_event_type() -> String {
    "ai.tokens".to_string()
}

fn default_metering_export_source() -> String {
    "ferrogate".to_string()
}

fn default_observability_prometheus_metrics_path() -> String {
    "/metrics".to_string()
}

fn default_observability_export_timeout_secs() -> u64 {
    3
}

/// #357: default running-presence TTL (seconds) for the observed-agent-activity
/// surface. Matches the value the issue's view contract proposes.
pub fn default_observability_observed_activity_running_ttl_secs() -> u64 {
    60
}

fn default_analytics_export_timeout_secs() -> u64 {
    3
}

fn default_analytics_batch_max_events() -> usize {
    500
}

fn default_analytics_flush_interval_millis() -> u64 {
    1_000
}

fn default_analytics_queue_capacity() -> usize {
    10_000
}

fn default_cache_ttl_secs() -> u64 {
    300
}

fn default_cache_max_records() -> usize {
    1_000
}

fn default_cache_semantic_similarity_threshold() -> f32 {
    0.92
}

fn default_tool_approval_timeout_secs() -> u64 {
    30
}

fn default_mcp_dispatch_timeout_secs() -> u64 {
    30
}

fn default_mcp_dispatch_max_concurrency() -> usize {
    32
}

fn default_storage_provider_order() -> Vec<StorageProviderKind> {
    ferrogate_storage::DEFAULT_DURABLE_PROVIDER_ORDER.to_vec()
}

fn default_storage_migration_mode() -> StorageMigrationMode {
    StorageMigrationMode::Auto
}

fn default_postgres_pool_size() -> usize {
    4
}

fn default_postgres_pool_acquire_timeout_millis() -> u64 {
    1_000
}

fn default_postgres_connect_timeout_secs() -> u64 {
    5
}

fn default_postgres_statement_timeout_millis() -> u64 {
    30_000
}

fn default_request_log_retention_records() -> usize {
    10_000
}

fn default_audit_event_retention_records() -> usize {
    10_000
}

fn default_guardrail_evaluation_retention_records() -> usize {
    10_000
}

fn default_billing_event_retention_records() -> usize {
    10_000
}

fn default_admin_list_limit() -> usize {
    100
}

fn default_admin_list_max_limit() -> usize {
    1_000
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            service_name: default_service_name(),
            log_bodies: false,
            access_log: AccessLogMode::default(),
            access_log_sample_rate: default_access_log_sample_rate(),
            access_log_error_rate_limit_per_sec: default_access_log_error_rate_limit_per_sec(),
            otlp_endpoint: None,
        }
    }
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: ObservabilityProvider::Vector,
            otlp_endpoint: None,
            cloudflare_collector_token_ref: None,
            cloudflare_default_tenant: None,
            prometheus_metrics_path: default_observability_prometheus_metrics_path(),
            export_timeout_secs: default_observability_export_timeout_secs(),
            observed_activity_running_ttl_secs:
                default_observability_observed_activity_running_ttl_secs(),
        }
    }
}

impl Default for AnalyticsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: AnalyticsProvider::Vector,
            required: false,
            vector_endpoint: None,
            clickhouse_url: None,
            clickhouse_url_env: None,
            export_timeout_secs: default_analytics_export_timeout_secs(),
            batch_max_events: default_analytics_batch_max_events(),
            flush_interval_millis: default_analytics_flush_interval_millis(),
            queue_capacity: default_analytics_queue_capacity(),
            request_log_retention_records: default_request_log_retention_records(),
            audit_event_retention_records: default_audit_event_retention_records(),
            guardrail_evaluation_retention_records: default_guardrail_evaluation_retention_records(
            ),
            billing_event_retention_records: default_billing_event_retention_records(),
        }
    }
}

impl Default for MeteringConfig {
    fn default() -> Self {
        Self {
            export_enabled: false,
            export_provider: MeteringExportProvider::default(),
            export_endpoint: default_metering_export_endpoint(),
            export_token_env: None,
            export_token: None,
            export_timeout_secs: default_metering_export_timeout_secs(),
            export_event_type: default_metering_export_event_type(),
            export_source: default_metering_export_source(),
            export_subject: MeteringExportSubject::default(),
        }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: CacheMode::ExactMatch,
            ttl_secs: default_cache_ttl_secs(),
            max_records: default_cache_max_records(),
            semantic_similarity_threshold: default_cache_semantic_similarity_threshold(),
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            provider: StorageProviderKind::Memory,
            required: false,
            provider_order: default_storage_provider_order(),
            libsql_url: None,
            libsql_auth_token: None,
            libsql_auth_token_env: None,
            postgres_dsn: None,
            postgres_dsn_env: None,
            supabase_dsn_env: None,
            postgres_pool_size: default_postgres_pool_size(),
            postgres_pool_acquire_timeout_millis: default_postgres_pool_acquire_timeout_millis(),
            postgres_tls_mode: PostgresTlsMode::default(),
            postgres_tls_ca_cert_path: None,
            postgres_connect_timeout_secs: default_postgres_connect_timeout_secs(),
            postgres_statement_timeout_millis: default_postgres_statement_timeout_millis(),
            postgres_schema: None,
            postgres_search_path: Vec::new(),
            d1_control_database_id: None,
            d1_tenant_databases: std::collections::BTreeMap::new(),
            migration_mode: default_storage_migration_mode(),
            admin_list_default_limit: default_admin_list_limit(),
            admin_list_max_limit: default_admin_list_max_limit(),
        }
    }
}

impl Default for ReliabilityConfig {
    fn default() -> Self {
        Self {
            provider_circuit_breaker_failure_threshold: None,
            provider_circuit_breaker_cooldown_secs: None,
            provider_dispatch_timeout_secs: None,
            provider_dispatch_max_retries: None,
            provider_response_body_max_bytes: None,
            tool_approval_timeout_secs: default_tool_approval_timeout_secs(),
            mcp_dispatch_timeout_secs: default_mcp_dispatch_timeout_secs(),
            mcp_dispatch_max_concurrency: default_mcp_dispatch_max_concurrency(),
            graceful_shutdown_grace_period_secs: None,
            graceful_shutdown_timeout_secs: None,
            graceful_upgrade_pid_file: None,
            graceful_upgrade_sock: None,
            graceful_upgrade_sock_retries: None,
        }
    }
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cluster_id: default_cluster_id(),
            node_id: default_cluster_node_id(),
            node_region: None,
            node_zone: None,
            state_backend: default_cluster_state_backend(),
            file_state_path: None,
            counter_backend: default_cluster_counter_backend(),
            redis_url: None,
            counter_timeout_millis: default_cluster_counter_timeout_millis(),
            heartbeat_interval_secs: default_cluster_heartbeat_interval_secs(),
            config_poll_interval_secs: default_cluster_config_poll_interval_secs(),
            snapshot_signing_key: None,
            snapshot_signing_key_id: None,
            snapshot_trusted_keys: Vec::new(),
            snapshot_tenant_id: None,
            snapshot_deployment_id: None,
            snapshot_max_age_secs: default_cluster_snapshot_max_age_secs(),
        }
    }
}

impl Default for AuthServiceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_auth_service_endpoint(),
            timeout_millis: default_auth_service_timeout_millis(),
            max_retries: 0,
            retry_backoff_millis: default_auth_service_retry_backoff_millis(),
        }
    }
}

impl Default for AgentRuntimeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: AgentRuntimeProvider::ManagedWorker,
            max_turns: default_agent_runtime_max_turns(),
            timeout_millis: default_agent_runtime_timeout_millis(),
            external: AgentRuntimeExternalConfig::default(),
            managed_worker: AgentRuntimeManagedWorkerConfig::default(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            admin: AdminConfig::default(),
            tls: TlsConfig::default(),
            auth_service: AuthServiceConfig::default(),
            billing_service: BillingServiceConfig::default(),
            admin_api: AdminApiConfig::default(),
            control_api: None,
            admin_api_alias: None,
            providers: Vec::new(),
            models: Vec::new(),
            api_keys: Vec::new(),
            policies: Vec::new(),
            gateway_configs: Vec::new(),
            agent_workflows: Vec::new(),
            skill_packages: Vec::new(),
            prompt_templates: Vec::new(),
            guardrails: Vec::new(),
            plugins: Vec::new(),
            extensions: Vec::new(),
            mcp_servers: Vec::new(),
            agent_upstreams: Vec::new(),
            telemetry: TelemetryConfig::default(),
            billing_alerts: BillingAlertsConfig::default(),
            observability: ObservabilityConfig::default(),
            analytics: AnalyticsConfig::default(),
            metering: MeteringConfig::default(),
            cache: CacheConfig::default(),
            storage: StorageConfig::default(),
            reliability: ReliabilityConfig::default(),
            limits: LimitsConfig::default(),
            agent_runtime: AgentRuntimeConfig::default(),
            cluster: ClusterConfig::default(),
            upstreams: Vec::new(),
            routes: Vec::new(),
            network_access: NetworkAccessConfig::default(),
            asset_bucket: AssetBucketConfig::default(),
            scheduler: SchedulerConfig::default(),
            asset_lifecycle: AssetLifecycleConfig::default(),
            x402_sweeper: X402SweeperConfig::default(),
            x402_reconciler: X402ReconcilerConfig::default(),
            x402_spend_policies: Vec::new(),
            asset_egress_price_per_gb: None,
            cloudflare: None,
            tenancy: TenancyConfig::default(),
            auth: AuthConfig::default(),
        }
    }
}
