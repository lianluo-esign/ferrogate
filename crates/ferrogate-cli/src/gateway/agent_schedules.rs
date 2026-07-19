// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-19
// description: Admin management surface for time-based agent schedules (#251,
// follow-up to the #246 scheduler): /admin/v1/agent-schedules CRUD +
// run-now + pause/resume (via `enabled`) + fire-history. Tenant/workspace
// scoped through the same auth machinery as the rest of /admin/v1/*.

use std::time::{SystemTime, UNIX_EPOCH};

use http::{Method, StatusCode};
use pingora::{proxy::Session, Result as PingoraResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use ferrogate_storage::{
    CatchupPolicy, OverlapPolicy, ScheduleSpecKind, ScheduleTargetKind, StoredAgentSchedule,
    StoredAgentScheduleFire,
};

use super::body::read_request_body;
use super::local::admin_audit_event_draft_for_target;
use super::{FerroGateway, ProxyContext};
use crate::{
    auth::{authenticate, authorize_tenant_scope, enforce_tenant_filter, AuthContext},
    responses::{write_json_error, write_json_error_and_close, write_json_response, AdminList},
};

const MAX_BODY_BYTES: usize = 64 * 1024;
/// Newest fire-history rows returned by `GET .../{id}/fires`.
const FIRE_HISTORY_LIMIT: i64 = 100;

impl FerroGateway {
    /// Dispatch for the whole `/admin/v1/agent-schedules[...]` surface. The
    /// route group resolves any of these paths here; this fn fans out by the
    /// path suffix (`/run-now`, `/fires`, or a bare `{id}`) and method.
    pub(super) async fn handle_admin_agent_schedules(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
        path: &str,
        query: Option<&str>,
    ) -> PingoraResult<()> {
        if path == "/admin/v1/agent-schedules" {
            return match *method {
                Method::GET => {
                    self.handle_admin_agent_schedule_list(session, ctx, headers, query)
                        .await
                }
                Method::POST => {
                    self.handle_admin_agent_schedule_upsert(session, ctx, headers, None)
                        .await
                }
                _ => method_not_allowed(session, ctx).await,
            };
        }

        let Some(rest) = path
            .strip_prefix("/admin/v1/agent-schedules/")
            .filter(|rest| !rest.is_empty())
        else {
            return not_found(session, ctx).await;
        };

        if let Some(id) = rest.strip_suffix("/run-now") {
            if id.is_empty() || id.contains('/') {
                return not_found(session, ctx).await;
            }
            return match *method {
                Method::POST => {
                    self.handle_admin_agent_schedule_run_now(session, ctx, headers, id)
                        .await
                }
                _ => method_not_allowed(session, ctx).await,
            };
        }

        if let Some(id) = rest.strip_suffix("/fires") {
            if id.is_empty() || id.contains('/') {
                return not_found(session, ctx).await;
            }
            return match *method {
                Method::GET => {
                    self.handle_admin_agent_schedule_fires(session, ctx, headers, id)
                        .await
                }
                _ => method_not_allowed(session, ctx).await,
            };
        }

        // A bare `{id}` -- reject any deeper/unknown sub-path.
        if rest.contains('/') {
            return not_found(session, ctx).await;
        }
        match *method {
            Method::GET => {
                self.handle_admin_agent_schedule_get(session, ctx, headers, rest)
                    .await
            }
            Method::PUT | Method::PATCH => {
                self.handle_admin_agent_schedule_upsert(session, ctx, headers, Some(rest))
                    .await
            }
            Method::DELETE => {
                self.handle_admin_agent_schedule_delete(session, ctx, headers, rest)
                    .await
            }
            _ => method_not_allowed(session, ctx).await,
        }
    }

    async fn handle_admin_agent_schedule_list(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        query: Option<&str>,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(auth) => auth,
            Err(error) => return write_auth_error(session, ctx, error).await,
        };
        // A tenant-scoped key is pinned to its own tenant; a platform operator
        // may narrow to a `?tenant=`/`?workspace=` filter or see every tenant.
        let requested_tenant =
            query_param(query, "tenant").or_else(|| query_param(query, "tenant_id"));
        let workspace =
            query_param(query, "workspace").or_else(|| query_param(query, "workspace_id"));
        let tenant = enforce_tenant_filter(&auth, requested_tenant);
        let schedules = match tenant {
            Some(tenant) => {
                state
                    .admin_list_agent_schedules(&tenant, workspace.as_deref())
                    .await
            }
            None => state.admin_list_all_agent_schedules().await,
        };
        match schedules {
            Ok(schedules) => {
                let data = schedules.iter().map(admin_agent_schedule).collect();
                write_json_response(
                    session,
                    StatusCode::OK,
                    &AdminList::new(data),
                    &ctx.request_id,
                )
                .await
            }
            Err(error) => storage_error(session, ctx, error.to_string()).await,
        }
    }

    async fn handle_admin_agent_schedule_get(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        id: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(auth) => auth,
            Err(error) => return write_auth_error(session, ctx, error).await,
        };
        let schedule = match self.load_scoped_schedule(session, ctx, &auth, id).await? {
            Some(schedule) => schedule,
            None => return Ok(()),
        };
        write_json_response(
            session,
            StatusCode::OK,
            &AdminAgentScheduleMutationResponse {
                object: "agent_schedule",
                agent_schedule: admin_agent_schedule(&schedule),
            },
            &ctx.request_id,
        )
        .await
    }

    async fn handle_admin_agent_schedule_fires(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        id: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(auth) => auth,
            Err(error) => return write_auth_error(session, ctx, error).await,
        };
        // Resolve + tenant-check the schedule first so a tenant-scoped caller
        // cannot read another tenant's fire history by id.
        if self
            .load_scoped_schedule(session, ctx, &auth, id)
            .await?
            .is_none()
        {
            return Ok(());
        }
        match state
            .admin_list_agent_schedule_fires(id, FIRE_HISTORY_LIMIT)
            .await
        {
            Ok(fires) => {
                let data = fires.iter().map(admin_agent_schedule_fire).collect();
                write_json_response(
                    session,
                    StatusCode::OK,
                    &AdminList::new(data),
                    &ctx.request_id,
                )
                .await
            }
            Err(error) => storage_error(session, ctx, error.to_string()).await,
        }
    }

    async fn handle_admin_agent_schedule_upsert(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        path_id: Option<&str>,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "admin.write", &ctx.request_id) {
            Ok(auth) => auth,
            Err(error) => return write_auth_error(session, ctx, error).await,
        };

        // On PUT/PATCH the schedule must exist and be owned by the caller's
        // tenant; the existing row is the merge base for a partial PATCH.
        let existing = match path_id {
            Some(id) => match self.load_scoped_schedule(session, ctx, &auth, id).await? {
                Some(schedule) => Some(schedule),
                None => return Ok(()),
            },
            None => None,
        };

        let body = match read_request_body(session, MAX_BODY_BYTES).await? {
            Ok(body) => body,
            Err(limit) => {
                return write_json_error_and_close(
                    session,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "payload_too_large",
                    format!(
                        "request body exceeds maximum size of {} bytes",
                        limit.max_bytes
                    ),
                    &ctx.request_id,
                )
                .await;
            }
        };
        let mutation = match serde_json::from_slice::<AdminAgentScheduleMutation>(&body) {
            Ok(mutation) => mutation,
            Err(error) => {
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_request_body",
                    format!("request body must be a JSON agent schedule object: {error}"),
                    &ctx.request_id,
                )
                .await;
            }
        };

        let now = now_unix_seconds();
        let schedule = match agent_schedule_from_mutation(path_id, mutation, existing.as_ref(), now)
        {
            Ok(schedule) => schedule,
            Err(message) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "agent_schedule.upsert",
                    path_id.unwrap_or("new"),
                    "rejected",
                    message.clone(),
                ));
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_agent_schedule",
                    message,
                    &ctx.request_id,
                )
                .await;
            }
        };
        // A tenant-scoped caller may only create/replace inside its own tenant.
        if let Err(error) = authorize_tenant_scope(&auth, &schedule.tenant_id) {
            return write_auth_error(session, ctx, error).await;
        }

        let schedule_id = schedule.schedule_id.clone();
        match state.admin_upsert_agent_schedule(schedule.clone()).await {
            Ok(()) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "agent_schedule.upsert",
                    &schedule_id,
                    "committed",
                    format!("agent schedule {schedule_id} committed"),
                ));
                write_json_response(
                    session,
                    if path_id.is_some() {
                        StatusCode::OK
                    } else {
                        StatusCode::CREATED
                    },
                    &AdminAgentScheduleMutationResponse {
                        object: "agent_schedule",
                        agent_schedule: admin_agent_schedule(&schedule),
                    },
                    &ctx.request_id,
                )
                .await
            }
            Err(error) => {
                let message = error.to_string();
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "agent_schedule.upsert",
                    &schedule_id,
                    "rejected",
                    message.clone(),
                ));
                storage_error(session, ctx, message).await
            }
        }
    }

    async fn handle_admin_agent_schedule_delete(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        id: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "admin.write", &ctx.request_id) {
            Ok(auth) => auth,
            Err(error) => return write_auth_error(session, ctx, error).await,
        };
        if self
            .load_scoped_schedule(session, ctx, &auth, id)
            .await?
            .is_none()
        {
            return Ok(());
        }
        match state.admin_delete_agent_schedule(id).await {
            Ok(true) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "agent_schedule.delete",
                    id,
                    "committed",
                    format!("agent schedule {id} deleted"),
                ));
                write_json_response(
                    session,
                    StatusCode::OK,
                    &crate::responses::AdminDeleteResponse {
                        object: "agent_schedule",
                        id: id.to_string(),
                        deleted: true,
                    },
                    &ctx.request_id,
                )
                .await
            }
            Ok(false) => schedule_not_found(session, ctx, id).await,
            Err(error) => storage_error(session, ctx, error.to_string()).await,
        }
    }

    async fn handle_admin_agent_schedule_run_now(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        id: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "admin.write", &ctx.request_id) {
            Ok(auth) => auth,
            Err(error) => return write_auth_error(session, ctx, error).await,
        };
        let schedule = match self.load_scoped_schedule(session, ctx, &auth, id).await? {
            Some(schedule) => schedule,
            None => return Ok(()),
        };
        match state.run_agent_schedule_now(&schedule).await {
            Ok(fire) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "agent_schedule.run_now",
                    id,
                    fire.outcome.as_str(),
                    format!(
                        "manual run-now for agent schedule {id}: {}",
                        fire.outcome.as_str()
                    ),
                ));
                write_json_response(
                    session,
                    StatusCode::ACCEPTED,
                    &AdminAgentScheduleRunNowResponse {
                        object: "agent_schedule_fire",
                        fire: admin_agent_schedule_fire(&fire),
                    },
                    &ctx.request_id,
                )
                .await
            }
            Err(error) => storage_error(session, ctx, error.to_string()).await,
        }
    }

    /// Loads a schedule by id and enforces tenant ownership. On a miss or a
    /// cross-tenant denial this writes the response and returns `Ok(None)`; the
    /// caller then returns without writing again.
    async fn load_scoped_schedule(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        auth: &AuthContext,
        id: &str,
    ) -> PingoraResult<Option<StoredAgentSchedule>> {
        let state = self.state.current();
        match state.admin_get_agent_schedule(id).await {
            Ok(Some(schedule)) => {
                if let Err(error) = authorize_tenant_scope(auth, &schedule.tenant_id) {
                    write_auth_error(session, ctx, error).await?;
                    return Ok(None);
                }
                Ok(Some(schedule))
            }
            Ok(None) => {
                schedule_not_found(session, ctx, id).await?;
                Ok(None)
            }
            Err(error) => {
                storage_error(session, ctx, error.to_string()).await?;
                Ok(None)
            }
        }
    }
}

/// Wire representation of a stored schedule. `target` is the parsed
/// `target_json` object so callers see structured JSON, not a string.
#[derive(Debug, Serialize)]
struct AdminAgentSchedule {
    object: &'static str,
    id: String,
    tenant_id: String,
    workspace_id: String,
    name: String,
    enabled: bool,
    spec_kind: &'static str,
    cron_expr: Option<String>,
    timezone: String,
    interval_secs: Option<i64>,
    target_kind: &'static str,
    target: Value,
    overlap_policy: &'static str,
    catchup_policy: &'static str,
    jitter_secs: i64,
    next_fire_at_unix: Option<i64>,
    last_fire_at_unix: Option<i64>,
    created_at_unix: i64,
    updated_at_unix: i64,
    revision: i64,
}

#[derive(Debug, Serialize)]
struct AdminAgentScheduleFire {
    object: &'static str,
    fire_id: String,
    schedule_id: String,
    scheduled_fire_at_unix: i64,
    fired_at_unix: i64,
    node_id: Option<String>,
    outcome: &'static str,
    dispatch_id: Option<String>,
    run_id: Option<String>,
    detail: Option<String>,
}

#[derive(Debug, Serialize)]
struct AdminAgentScheduleMutationResponse {
    object: &'static str,
    agent_schedule: AdminAgentSchedule,
}

#[derive(Debug, Serialize)]
struct AdminAgentScheduleRunNowResponse {
    object: &'static str,
    fire: AdminAgentScheduleFire,
}

/// Create/replace/patch payload. Every field except `id` is optional so a
/// PATCH can toggle a single field (e.g. `{"enabled": false}` to pause);
/// missing fields inherit from the existing row on update, or fail validation
/// when required on create.
#[derive(Debug, Deserialize)]
struct AdminAgentScheduleMutation {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    workspace_id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    spec_kind: Option<String>,
    #[serde(default)]
    cron_expr: Option<String>,
    #[serde(default)]
    timezone: Option<String>,
    #[serde(default)]
    interval_secs: Option<i64>,
    #[serde(default)]
    target_kind: Option<String>,
    #[serde(default)]
    target: Option<Value>,
    #[serde(default)]
    overlap_policy: Option<String>,
    #[serde(default)]
    catchup_policy: Option<String>,
    #[serde(default)]
    jitter_secs: Option<i64>,
}

fn admin_agent_schedule(schedule: &StoredAgentSchedule) -> AdminAgentSchedule {
    AdminAgentSchedule {
        object: "agent_schedule",
        id: schedule.schedule_id.clone(),
        tenant_id: schedule.tenant_id.clone(),
        workspace_id: schedule.workspace_id.clone(),
        name: schedule.name.clone(),
        enabled: schedule.enabled,
        spec_kind: schedule.spec_kind.as_str(),
        cron_expr: schedule.cron_expr.clone(),
        timezone: schedule.timezone.clone(),
        interval_secs: schedule.interval_secs,
        target_kind: schedule.target_kind.as_str(),
        target: serde_json::from_str(&schedule.target_json).unwrap_or(Value::Null),
        overlap_policy: schedule.overlap_policy.as_str(),
        catchup_policy: schedule.catchup_policy.as_str(),
        jitter_secs: schedule.jitter_secs,
        next_fire_at_unix: schedule.next_fire_at_unix,
        last_fire_at_unix: schedule.last_fire_at_unix,
        created_at_unix: schedule.created_at_unix,
        updated_at_unix: schedule.updated_at_unix,
        revision: schedule.revision,
    }
}

fn admin_agent_schedule_fire(fire: &StoredAgentScheduleFire) -> AdminAgentScheduleFire {
    AdminAgentScheduleFire {
        object: "agent_schedule_fire",
        fire_id: fire.fire_id.clone(),
        schedule_id: fire.schedule_id.clone(),
        scheduled_fire_at_unix: fire.scheduled_fire_at_unix,
        fired_at_unix: fire.fired_at_unix,
        node_id: fire.node_id.clone(),
        outcome: fire.outcome.as_str(),
        dispatch_id: fire.dispatch_id.clone(),
        run_id: fire.run_id.clone(),
        detail: fire.detail.clone(),
    }
}

/// Build a durable schedule from a mutation, merging over `existing` on update
/// and validating the spec (cron/interval + timezone) by computing the first
/// fire from `now`. Returns a human-readable message on any invalid field.
fn agent_schedule_from_mutation(
    path_id: Option<&str>,
    mutation: AdminAgentScheduleMutation,
    existing: Option<&StoredAgentSchedule>,
    now: i64,
) -> Result<StoredAgentSchedule, String> {
    let id = match (path_id, mutation.id.as_deref()) {
        (Some(path_id), Some(body_id)) if path_id != body_id => {
            return Err("request path id and body id must match".to_string());
        }
        (Some(path_id), _) => path_id.to_string(),
        (None, Some(body_id)) => body_id.trim().to_string(),
        (None, None) => return Err("agent schedule id is required".to_string()),
    };
    if id.trim().is_empty() {
        return Err("agent schedule id must not be empty".to_string());
    }

    let tenant_id = pick_required(
        "tenant_id",
        mutation.tenant_id,
        existing.map(|s| s.tenant_id.clone()),
    )?;
    let workspace_id = pick_required(
        "workspace_id",
        mutation.workspace_id,
        existing.map(|s| s.workspace_id.clone()),
    )?;
    let name = pick_required("name", mutation.name, existing.map(|s| s.name.clone()))?;

    let spec_kind = match mutation.spec_kind {
        Some(raw) => ScheduleSpecKind::from_str_opt(&raw)
            .ok_or_else(|| format!("unknown spec_kind '{raw}' (expected 'cron' or 'interval')"))?,
        None => existing
            .map(|s| s.spec_kind)
            .ok_or_else(|| "spec_kind is required".to_string())?,
    };
    let target_kind = match mutation.target_kind {
        Some(raw) => ScheduleTargetKind::from_str_opt(&raw).ok_or_else(|| {
            format!("unknown target_kind '{raw}' (expected 'self_hosted_dispatch' or 'agent_run')")
        })?,
        None => existing
            .map(|s| s.target_kind)
            .ok_or_else(|| "target_kind is required".to_string())?,
    };
    let overlap_policy = match mutation.overlap_policy {
        Some(raw) => OverlapPolicy::from_str_opt(&raw)
            .ok_or_else(|| format!("unknown overlap_policy '{raw}'"))?,
        None => existing
            .map(|s| s.overlap_policy)
            .unwrap_or(OverlapPolicy::Skip),
    };
    let catchup_policy = match mutation.catchup_policy {
        Some(raw) => CatchupPolicy::from_str_opt(&raw)
            .ok_or_else(|| format!("unknown catchup_policy '{raw}'"))?,
        None => existing
            .map(|s| s.catchup_policy)
            .unwrap_or(CatchupPolicy::SkipMissed),
    };

    let cron_expr = mutation
        .cron_expr
        .or_else(|| existing.and_then(|s| s.cron_expr.clone()))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let timezone = mutation
        .timezone
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| existing.map(|s| s.timezone.clone()))
        .unwrap_or_else(|| "UTC".to_string());
    let interval_secs = mutation
        .interval_secs
        .or_else(|| existing.and_then(|s| s.interval_secs));
    let enabled = mutation
        .enabled
        .or_else(|| existing.map(|s| s.enabled))
        .unwrap_or(true);
    let jitter_secs = mutation
        .jitter_secs
        .or_else(|| existing.map(|s| s.jitter_secs))
        .unwrap_or(0);
    if jitter_secs < 0 {
        return Err("jitter_secs must not be negative".to_string());
    }
    let target_json = match mutation.target {
        Some(target) => {
            if !target.is_object() {
                return Err("target must be a JSON object".to_string());
            }
            serde_json::to_string(&target).map_err(|error| format!("invalid target: {error}"))?
        }
        None => existing
            .map(|s| s.target_json.clone())
            .unwrap_or_else(|| "{}".to_string()),
    };

    let mut schedule = StoredAgentSchedule {
        schedule_id: id,
        tenant_id,
        workspace_id,
        name,
        enabled,
        spec_kind,
        cron_expr,
        timezone,
        interval_secs,
        target_kind,
        target_json,
        overlap_policy,
        catchup_policy,
        jitter_secs,
        next_fire_at_unix: None,
        last_fire_at_unix: existing.and_then(|s| s.last_fire_at_unix),
        created_at_unix: existing.map(|s| s.created_at_unix).unwrap_or(now),
        updated_at_unix: now,
        revision: existing.map(|s| s.revision + 1).unwrap_or(1),
    };

    // Validate the spec and seed the first fire relative to `now`. An
    // interval schedule requires a positive interval; a cron schedule requires
    // a valid expression + timezone (surfaced as `compute_next_fire_at` errors).
    match spec_kind {
        ScheduleSpecKind::Interval => {
            if interval_secs.is_none_or(|secs| secs <= 0) {
                return Err("interval schedule requires interval_secs > 0".to_string());
            }
        }
        ScheduleSpecKind::Cron => {
            if schedule.cron_expr.is_none() {
                return Err("cron schedule requires a non-empty cron_expr".to_string());
            }
        }
    }
    schedule.next_fire_at_unix = schedule
        .compute_next_fire_at(now)
        .map_err(|error| error.to_string())?;

    Ok(schedule)
}

fn pick_required(
    field: &str,
    provided: Option<String>,
    existing: Option<String>,
) -> Result<String, String> {
    let value = provided
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or(existing);
    value
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{field} is required"))
}

fn query_param(query: Option<&str>, key: &str) -> Option<String> {
    let query = query?;
    query.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name == key && !value.is_empty()).then(|| value.to_string())
    })
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

async fn method_not_allowed(session: &mut Session, ctx: &ProxyContext) -> PingoraResult<()> {
    write_json_error(
        session,
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        "agent schedule endpoint supports GET, POST, PUT, PATCH, DELETE, and POST .../run-now",
        &ctx.request_id,
    )
    .await
}

async fn not_found(session: &mut Session, ctx: &ProxyContext) -> PingoraResult<()> {
    write_json_error(
        session,
        StatusCode::NOT_FOUND,
        "agent_schedule_endpoint_not_found",
        "agent schedule endpoint not found",
        &ctx.request_id,
    )
    .await
}

async fn schedule_not_found(
    session: &mut Session,
    ctx: &ProxyContext,
    id: &str,
) -> PingoraResult<()> {
    write_json_error(
        session,
        StatusCode::NOT_FOUND,
        "agent_schedule_not_found",
        format!("agent schedule {id} was not found"),
        &ctx.request_id,
    )
    .await
}

async fn storage_error(
    session: &mut Session,
    ctx: &ProxyContext,
    message: String,
) -> PingoraResult<()> {
    write_json_error(
        session,
        StatusCode::SERVICE_UNAVAILABLE,
        "storage_unavailable",
        message,
        &ctx.request_id,
    )
    .await
}

async fn write_auth_error(
    session: &mut Session,
    ctx: &ProxyContext,
    error: crate::auth::AuthError,
) -> PingoraResult<()> {
    write_json_error(
        session,
        error.status,
        error.code,
        error.message,
        &ctx.request_id,
    )
    .await
}

#[cfg(test)]
#[path = "agent_schedules_test.rs"]
mod agent_schedules_test;
