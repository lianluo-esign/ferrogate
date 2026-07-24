// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: AgentScheduleClient verb tests (issue #426) — assert each scheduling verb hits
//   the right /schedule/* route with the bearer token, instance name, and kind-specific task
//   shape; that invalid specs are rejected client-side with NO HTTP; and that the Worker's
//   error vocabulary (invalid_task/schedule_limit/denied) maps to typed errors. NO network.

use std::collections::VecDeque;
use std::sync::Mutex;

use ferrogate_cloudflare::{HttpMethod, HttpRequest, HttpResponse};
use serde_json::json;

use super::{
    AgentScheduleCancelSelector, AgentScheduleClient, AgentScheduleError, AgentScheduleKind,
    AgentScheduleListCriteria, AgentScheduleTaskSpec, AgentScheduleWhen,
};
use crate::cloudflare_agent_memory::AgentInstanceIdentity;
use crate::cloudflare_gateway_control::GatewayControlTransport;
use crate::cloudflare_worker::CloudflareControlSurfaceError;

/// A synchronous scripted transport: records requests, replays responses.
struct MockScheduleTransport {
    responses: Mutex<VecDeque<HttpResponse>>,
    captured: Mutex<Vec<HttpRequest>>,
}

impl MockScheduleTransport {
    fn new(responses: Vec<HttpResponse>) -> Self {
        Self {
            responses: Mutex::new(responses.into_iter().collect()),
            captured: Mutex::new(Vec::new()),
        }
    }

    fn last(&self) -> HttpRequest {
        self.captured.lock().unwrap().last().cloned().unwrap()
    }

    fn captured_len(&self) -> usize {
        self.captured.lock().unwrap().len()
    }
}

impl GatewayControlTransport for MockScheduleTransport {
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, CloudflareControlSurfaceError> {
        self.captured.lock().unwrap().push(request);
        Ok(self
            .responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("mock schedule transport ran out of responses"))
    }
}

fn ok(body: &str) -> HttpResponse {
    HttpResponse {
        status: 200,
        retry_after: None,
        body: body.as_bytes().to_vec(),
    }
}

fn status(code: u16, body: &str) -> HttpResponse {
    HttpResponse {
        status: code,
        retry_after: None,
        body: body.as_bytes().to_vec(),
    }
}

fn client(responses: Vec<HttpResponse>) -> AgentScheduleClient<MockScheduleTransport> {
    AgentScheduleClient::new(
        "https://ferrogate-agent-gateway.example.workers.dev",
        "control-secret",
        MockScheduleTransport::new(responses),
    )
}

fn identity() -> AgentInstanceIdentity {
    AgentInstanceIdentity::new("tenant-a", "sess-1", "run-9")
}

fn body_json(req: &HttpRequest) -> serde_json::Value {
    serde_json::from_slice(req.body.as_ref().unwrap()).unwrap()
}

fn created_body() -> &'static str {
    r#"{ "ok": true, "instance": "fg.tenant-a.sess-1.run-9", "replaced": 0,
         "schedule": { "id": "abc123", "taskId": "sync-report", "kind": "once",
                       "sdkType": "delayed", "callback": "runScheduledTask",
                       "time": 1753372800, "cron": null, "everySeconds": null,
                       "data": { "note": "n" } } }"#
}

// ---- schedule_create: kind-specific task shapes -----------------------------

#[test]
fn create_once_delay_posts_kind_once_with_delay_seconds() {
    let c = client(vec![ok(created_body())]);
    let spec = AgentScheduleTaskSpec::new("sync-report", AgentScheduleWhen::DelaySeconds(30))
        .with_data(json!({ "note": "n" }));
    let outcome = c.schedule_create(&identity(), &spec).unwrap();
    assert_eq!(outcome.schedule.id, "abc123");
    assert_eq!(outcome.schedule.task_id.as_deref(), Some("sync-report"));
    assert_eq!(outcome.replaced, 0);

    let req = c.transport().last();
    assert_eq!(req.method, HttpMethod::Post);
    assert_eq!(
        req.url,
        "https://ferrogate-agent-gateway.example.workers.dev/schedule/create"
    );
    assert_eq!(req.bearer_token, "control-secret");
    let body = body_json(&req);
    assert_eq!(body["instance"], "fg.tenant-a.sess-1.run-9");
    assert_eq!(body["task"]["taskId"], "sync-report");
    assert_eq!(body["task"]["kind"], "once");
    assert_eq!(body["task"]["delaySeconds"], 30);
    assert_eq!(body["task"]["data"]["note"], "n");
    assert!(body["task"].get("at").is_none());
}

#[test]
fn create_once_at_posts_the_absolute_instant() {
    let c = client(vec![ok(created_body())]);
    let spec = AgentScheduleTaskSpec::new(
        "sync-report",
        AgentScheduleWhen::At("2026-08-01T00:00:00Z".into()),
    );
    c.schedule_create(&identity(), &spec).unwrap();
    let body = body_json(&c.transport().last());
    assert_eq!(body["task"]["kind"], "once");
    assert_eq!(body["task"]["at"], "2026-08-01T00:00:00Z");
    assert!(body["task"].get("delaySeconds").is_none());
}

#[test]
fn create_cron_posts_kind_cron_with_expression() {
    let c = client(vec![ok(created_body())]);
    let spec = AgentScheduleTaskSpec::new("nightly", AgentScheduleWhen::Cron("0 3 * * *".into()));
    c.schedule_create(&identity(), &spec).unwrap();
    let body = body_json(&c.transport().last());
    assert_eq!(body["task"]["kind"], "cron");
    assert_eq!(body["task"]["cron"], "0 3 * * *");
}

#[test]
fn create_interval_posts_kind_interval_with_every_seconds() {
    let c = client(vec![ok(created_body())]);
    let spec = AgentScheduleTaskSpec::new("heartbeat", AgentScheduleWhen::EverySeconds(15));
    c.schedule_create(&identity(), &spec).unwrap();
    let body = body_json(&c.transport().last());
    assert_eq!(body["task"]["kind"], "interval");
    assert_eq!(body["task"]["everySeconds"], 15);
}

#[test]
fn create_reports_replaced_rows_from_the_duplicate_guard() {
    // The Worker's cancel-before-recreate (agents#1049 guard) reports how
    // many stale rows it removed before creating the replacement.
    let c = client(vec![ok(
        r#"{ "ok": true, "instance": "fg.tenant-a.sess-1.run-9", "replaced": 2,
             "schedule": { "id": "def456", "taskId": "heartbeat", "kind": "interval",
                           "sdkType": "delayed", "callback": "runScheduledTask",
                           "time": 1753372815, "cron": null, "everySeconds": 15,
                           "data": null } }"#,
    )]);
    let spec = AgentScheduleTaskSpec::new("heartbeat", AgentScheduleWhen::EverySeconds(15));
    let outcome = c.schedule_create(&identity(), &spec).unwrap();
    assert_eq!(outcome.replaced, 2);
    assert_eq!(outcome.schedule.every_seconds, Some(15));
    assert_eq!(outcome.schedule.callback, "runScheduledTask");
}

// ---- Client-side validation: invalid specs send NO HTTP ---------------------

#[test]
fn create_rejects_bad_task_ids_without_http() {
    let c = client(vec![]);
    for task_id in ["", "has space", "a/b", &"x".repeat(129)] {
        let spec = AgentScheduleTaskSpec::new(task_id, AgentScheduleWhen::DelaySeconds(1));
        let err = c.schedule_create(&identity(), &spec).unwrap_err();
        assert!(
            matches!(err, AgentScheduleError::InvalidTask(_)),
            "task_id {task_id:?}: got {err:?}"
        );
    }
    assert_eq!(
        c.transport().captured_len(),
        0,
        "invalid specs must send no HTTP"
    );
}

#[test]
fn create_rejects_zero_interval_and_empty_cron_without_http() {
    let c = client(vec![]);
    for when in [
        AgentScheduleWhen::EverySeconds(0),
        AgentScheduleWhen::Cron("  ".into()),
    ] {
        let spec = AgentScheduleTaskSpec::new("t1", when);
        let err = c.schedule_create(&identity(), &spec).unwrap_err();
        assert!(
            matches!(err, AgentScheduleError::InvalidTask(_)),
            "got {err:?}"
        );
    }
    assert_eq!(c.transport().captured_len(), 0);
}

#[test]
fn invalid_identity_is_rejected_before_any_http() {
    let c = client(vec![]);
    let bad = AgentInstanceIdentity::new("tenant.a", "s", "r");
    let spec = AgentScheduleTaskSpec::new("t1", AgentScheduleWhen::DelaySeconds(1));
    let err = c.schedule_create(&bad, &spec).unwrap_err();
    assert!(
        matches!(err, AgentScheduleError::InvalidIdentity(_)),
        "got {err:?}"
    );
    assert_eq!(c.transport().captured_len(), 0);
}

// ---- schedule_list ----------------------------------------------------------

#[test]
fn list_posts_criteria_and_maps_records() {
    let c = client(vec![ok(
        r#"{ "ok": true, "instance": "fg.tenant-a.sess-1.run-9", "count": 1,
             "schedules": [
               { "id": "abc123", "taskId": "nightly", "kind": "cron",
                 "sdkType": "cron", "callback": "runScheduledTask",
                 "time": 1753412400, "cron": "0 3 * * *", "everySeconds": null,
                 "data": null }
             ] }"#,
    )]);
    let criteria = AgentScheduleListCriteria {
        task_id: Some("nightly".into()),
        kind: Some(AgentScheduleKind::Cron),
    };
    let list = c.schedule_list(&identity(), &criteria).unwrap();
    assert_eq!(list.count, 1);
    assert_eq!(list.schedules[0].cron.as_deref(), Some("0 3 * * *"));
    assert_eq!(list.schedules[0].sdk_type, "cron");

    let req = c.transport().last();
    assert_eq!(
        req.url,
        "https://ferrogate-agent-gateway.example.workers.dev/schedule/list"
    );
    let body = body_json(&req);
    assert_eq!(body["taskId"], "nightly");
    assert_eq!(body["kind"], "cron");
}

#[test]
fn list_without_criteria_omits_the_filters() {
    let c = client(vec![ok(
        r#"{ "ok": true, "instance": "fg.tenant-a.sess-1.run-9", "count": 0, "schedules": [] }"#,
    )]);
    c.schedule_list(&identity(), &AgentScheduleListCriteria::default())
        .unwrap();
    let body = body_json(&c.transport().last());
    assert!(
        body.get("taskId").is_none(),
        "filters must be omitted: {body}"
    );
    assert!(
        body.get("kind").is_none(),
        "filters must be omitted: {body}"
    );
}

// ---- schedule_cancel --------------------------------------------------------

#[test]
fn cancel_by_task_id_posts_task_id_and_maps_the_count() {
    let c = client(vec![ok(
        r#"{ "ok": true, "instance": "fg.tenant-a.sess-1.run-9", "cancelled": 2 }"#,
    )]);
    let outcome = c
        .schedule_cancel(
            &identity(),
            &AgentScheduleCancelSelector::TaskId("heartbeat".into()),
        )
        .unwrap();
    assert_eq!(outcome.cancelled, 2);

    let req = c.transport().last();
    assert_eq!(
        req.url,
        "https://ferrogate-agent-gateway.example.workers.dev/schedule/cancel"
    );
    let body = body_json(&req);
    assert_eq!(body["taskId"], "heartbeat");
    assert!(body.get("scheduleId").is_none());
}

#[test]
fn cancel_by_schedule_id_posts_schedule_id() {
    let c = client(vec![ok(
        r#"{ "ok": true, "instance": "fg.tenant-a.sess-1.run-9", "cancelled": 1 }"#,
    )]);
    c.schedule_cancel(
        &identity(),
        &AgentScheduleCancelSelector::ScheduleId("abc123".into()),
    )
    .unwrap();
    let body = body_json(&c.transport().last());
    assert_eq!(body["scheduleId"], "abc123");
    assert!(body.get("taskId").is_none());
}

#[test]
fn cancel_of_a_missing_task_is_ok_with_zero_cancelled() {
    // The pinned SDK's cancelSchedule returns true even for missing ids; the
    // Worker checks existence, so a miss is Ok(cancelled == 0), not an error.
    let c = client(vec![ok(
        r#"{ "ok": true, "instance": "fg.tenant-a.sess-1.run-9", "cancelled": 0 }"#,
    )]);
    let outcome = c
        .schedule_cancel(
            &identity(),
            &AgentScheduleCancelSelector::TaskId("never-created".into()),
        )
        .unwrap();
    assert_eq!(outcome.cancelled, 0);
}

// ---- Error mapping ----------------------------------------------------------

#[test]
fn denied_bearer_maps_to_denied() {
    let c = client(vec![status(403, r#"{ "error": "invalid bearer token" }"#)]);
    let spec = AgentScheduleTaskSpec::new("t1", AgentScheduleWhen::DelaySeconds(1));
    let err = c.schedule_create(&identity(), &spec).unwrap_err();
    assert!(matches!(err, AgentScheduleError::Denied(_)), "got {err:?}");
}

#[test]
fn worker_side_invalid_task_422_maps_to_invalid_task() {
    let c = client(vec![status(
        422,
        r#"{ "error": "invalid_task", "message": "task.kind must be once/cron/interval" }"#,
    )]);
    let spec = AgentScheduleTaskSpec::new("t1", AgentScheduleWhen::DelaySeconds(1));
    let err = c.schedule_create(&identity(), &spec).unwrap_err();
    match err {
        AgentScheduleError::InvalidTask(m) => {
            assert!(m.contains("once/cron/interval"), "got {m}")
        }
        other => panic!("expected InvalidTask, got {other:?}"),
    }
}

#[test]
fn schedule_limit_429_maps_to_limit_exceeded() {
    let c = client(vec![status(
        429,
        r#"{ "error": "schedule_limit", "message": "instance already holds 100 schedules (cap 100)" }"#,
    )]);
    let spec = AgentScheduleTaskSpec::new("t1", AgentScheduleWhen::Cron("* * * * *".into()));
    let err = c.schedule_create(&identity(), &spec).unwrap_err();
    assert!(
        matches!(err, AgentScheduleError::LimitExceeded(_)),
        "got {err:?}"
    );
}

#[test]
fn other_failures_map_to_request_failed_with_verb_and_status() {
    let c = client(vec![status(
        502,
        r#"{ "error": "schedule call failed: boom" }"#,
    )]);
    let err = c
        .schedule_list(&identity(), &AgentScheduleListCriteria::default())
        .unwrap_err();
    match err {
        AgentScheduleError::RequestFailed { verb, status, .. } => {
            assert_eq!(verb, "schedule_list");
            assert_eq!(status, 502);
        }
        other => panic!("expected RequestFailed, got {other:?}"),
    }
}
