// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: AppState assembly for the observed-agent-activity surface
// (#357). Gathers already-recorded evidence -- request logs (recency +
// request count), settled billing/metering (token/cost), verified
// managed/self-hosted/agent-run identities (the attribution exclusion set),
// and virtual-key names (the redacted credential hint) -- and hands it to the
// pure `derive_observed_agent_activity` presentation pass. No new hot-path
// write or synchronous storage work is added; every read here is an existing
// admin-read accessor.

use std::collections::{HashMap, HashSet};

use super::*;
use crate::gateway::observed_agent_activity::{
    derive_observed_agent_activity, resolve_observed_activity_running_ttl_seconds,
    ObservedActivityInputs, ObservedAgentActivity, UsageContribution,
    OBSERVED_ACTIVITY_RUNNING_TTL_ENV,
};

impl AppState {
    /// Build the tenant-scoped observed-unattributed-activity rows. `None`
    /// tenant_scope is the platform-operator cross-tenant view.
    pub(crate) fn observed_agent_activity(
        &self,
        tenant_scope: Option<&str>,
    ) -> Vec<ObservedAgentActivity> {
        let now_unix = now_unix_seconds().unwrap_or(0);

        // Operator-configurable running-presence TTL (#357): typed config value
        // (`observability.observed_activity_running_ttl_secs`, default 60),
        // overridable at runtime via the env knob without a config reload.
        let running_ttl_seconds = resolve_observed_activity_running_ttl_seconds(
            self.config.observability.observed_activity_running_ttl_secs,
            std::env::var(OBSERVED_ACTIVITY_RUNNING_TTL_ENV)
                .ok()
                .as_deref(),
        );

        // Recency + request-count evidence. `request_logs()` flushes the
        // deferred evidence writer first, keeping read-your-writes.
        let request_logs = self.request_logs();

        // Durable coalesced presence (#357): the recency signal that backs the
        // `running` decision. Read only the window that could still be running
        // ([now - ttl, now]); older rows can never flip a group to running.
        // Keyed by (tenant_id, api_key_id) -> MAX last-seen so the derivation
        // uses the fresher of this and the request-log evidence.
        let presence_window_start = now_unix.saturating_sub(running_ttl_seconds) as i64;
        let mut presence_last_seen: HashMap<(String, String), u64> = HashMap::new();
        for presence in crate::gateway::block_on_sync_bridge(
            self.repositories
                .list_observed_agent_presence_since(tenant_scope, presence_window_start),
        )
        .unwrap_or_default()
        {
            let last_seen = presence.last_seen_at_unix.max(0) as u64;
            presence_last_seen
                .entry((presence.tenant_id, presence.api_key_id))
                .and_modify(|existing| *existing = (*existing).max(last_seen))
                .or_insert(last_seen);
        }

        // Attribution exclusion set: run ids owned by a VERIFIED execution
        // identity. A request whose agent_run_id is here keeps that identity
        // and is never surfaced as Unknown. Assembled from managed-worker
        // sessions, self-hosted run dispatches, and recorded agent runs.
        let mut attributed_run_ids: HashSet<String> = HashSet::new();
        for session in
            crate::gateway::block_on_sync_bridge(self.repositories.managed_worker_sessions())
        {
            if !session.run_id.is_empty() {
                attributed_run_ids.insert(session.run_id);
            }
        }
        for dispatch in
            crate::gateway::block_on_sync_bridge(self.repositories.self_hosted_run_dispatches())
        {
            if !dispatch.run_id.is_empty() {
                attributed_run_ids.insert(dispatch.run_id);
            }
            if let Some(agent_run_id) = dispatch.agent_run_id {
                attributed_run_ids.insert(agent_run_id);
            }
        }
        for run in crate::gateway::block_on_sync_bridge(self.repositories.agent_runs()) {
            if !run.id.is_empty() {
                attributed_run_ids.insert(run.id);
            }
        }

        // Token/cost evidence for the same requests, folded from settled
        // billing/metering events. Missing evidence stays absent (never
        // invented). Multiple provider attempts for one request_id are summed.
        let mut usage_by_request_id: HashMap<String, UsageContribution> = HashMap::new();
        for event in self.metering_events() {
            let entry = usage_by_request_id
                .entry(event.request_id.clone())
                .or_default();
            entry.prompt_tokens = entry
                .prompt_tokens
                .saturating_add(event.usage.prompt_tokens);
            entry.completion_tokens = entry
                .completion_tokens
                .saturating_add(event.usage.completion_tokens);
            entry.total_tokens = entry.total_tokens.saturating_add(event.usage.total_tokens);
            if let Some(cost) = event.cost_usd {
                entry.cost_usd = Some(entry.cost_usd.unwrap_or(0.0) + cost);
            }
        }

        // Redacted credential hint: the virtual key's name. Best-effort -- a
        // failure to list key records must never fail the endpoint; the hint is
        // simply omitted.
        let mut credential_names: HashMap<String, String> = HashMap::new();
        for key in
            crate::gateway::block_on_sync_bridge(self.list_virtual_api_keys()).unwrap_or_default()
        {
            if let Some(scope) = tenant_scope {
                if key.tenant_id != scope {
                    continue;
                }
            }
            if !key.name.is_empty() {
                credential_names.insert(key.id, key.name);
            }
        }

        let inputs = ObservedActivityInputs {
            request_logs: &request_logs,
            attributed_run_ids: &attributed_run_ids,
            usage_by_request_id: &usage_by_request_id,
            credential_names: &credential_names,
            presence_last_seen: &presence_last_seen,
            tenant_scope,
            now_unix,
            running_ttl_seconds,
        };
        derive_observed_agent_activity(&inputs)
    }
}

#[cfg(test)]
#[path = "state_observed_activity_test.rs"]
mod state_observed_activity_test;
