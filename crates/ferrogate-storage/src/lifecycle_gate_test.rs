// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Unit tests for the #514 lifecycle decision AND for the chain
// WALK, which had no direct test at all when the slice first landed -- the hole
// it hid (a credential declaring only `project_id` never reading the tenant
// above it) was the issue's headline symptom. `tests/tenant_suspension_e2e.rs`
// pins the wiring against a live gateway.

use super::*;

use std::collections::HashMap;
use std::sync::Mutex;

fn chain(entries: &[(&'static str, &str, &str)]) -> Vec<LifecycleRef> {
    entries
        .iter()
        .map(|(kind, id, status)| LifecycleRef::new(kind, *id, status))
        .collect()
}

// --- the pure decision ---

#[test]
fn an_active_chain_passes_every_seam() {
    let chain = chain(&[
        ("tenant", "tenant-1", "active"),
        ("project", "proj-1", "active"),
        ("workspace", "ws-1", "active"),
    ]);
    for seam in [
        LifecycleSeam::Request,
        LifecycleSeam::Recovery,
        LifecycleSeam::Attach,
    ] {
        assert!(check_lifecycle_chain(seam, &chain).is_ok(), "{seam:?}");
    }
}

#[test]
fn an_empty_chain_passes_every_seam() {
    // Platform-operator keys (no organization_id) and keys pointing at rows
    // that do not exist resolve to an empty chain: absence is not suspension.
    for seam in [
        LifecycleSeam::Request,
        LifecycleSeam::Recovery,
        LifecycleSeam::Attach,
    ] {
        assert!(check_lifecycle_chain(seam, &[]).is_ok(), "{seam:?}");
    }
}

/// The billing-critical assertion: the live probe showed a pre-existing virtual
/// key still returning 200 from `/v1/models` after its tenant was suspended.
#[test]
fn a_suspended_tenant_stops_requests() {
    let chain = chain(&[
        ("tenant", "tenant-susp", "suspended"),
        ("project", "proj-susp", "active"),
        ("workspace", "ws-susp", "active"),
    ]);
    let rejection = check_lifecycle_chain(LifecycleSeam::Request, &chain)
        .expect_err("a suspended tenant must stop serving traffic");
    assert_eq!(rejection.http_status(), 403);
    assert_eq!(rejection.code(), "tenancy_suspended");
    assert_eq!(rejection.reference.kind, "tenant");
    assert_eq!(rejection.reference.id, "tenant-susp");
    assert!(
        rejection
            .message()
            .contains("tenant tenant-susp is suspended"),
        "{}",
        rejection.message()
    );
}

/// Suspension at any depth counts -- an operator who suspends only the
/// workspace must not be silently ignored because the tenant above it is fine.
#[test]
fn a_suspended_workspace_alone_stops_requests() {
    let chain = chain(&[
        ("tenant", "tenant-1", "active"),
        ("project", "proj-1", "active"),
        ("workspace", "ws-susp", "suspended"),
    ]);
    let rejection = check_lifecycle_chain(LifecycleSeam::Request, &chain)
        .expect_err("a suspended workspace must stop serving traffic");
    assert_eq!(rejection.reference.kind, "workspace");
    assert_eq!(rejection.code(), "tenancy_suspended");
}

#[test]
fn disabled_and_deleted_also_stop_requests_with_distinct_codes() {
    for (raw, expected_code) in [
        ("disabled", "tenancy_disabled"),
        ("deleted", "tenancy_deleted"),
    ] {
        let chain = chain(&[("tenant", "tenant-1", raw)]);
        let rejection = check_lifecycle_chain(LifecycleSeam::Request, &chain)
            .expect_err("a non-active tenant must stop serving traffic");
        assert_eq!(rejection.code(), expected_code, "for status {raw}");
    }
}

/// Finding 5: `disabled` must not be a one-way door. The Recovery seam -- the
/// lifecycle PUT/PATCH routes and the console session mint -- lets a
/// `disabled` row through so the tenant that turned its own project off can
/// reach the request that turns it back on. `suspended`/`deleted` still deny:
/// those are platform-operator actions, reversed with an operator key (which
/// carries no tenancy chain and so is never gated).
#[test]
fn the_recovery_seam_admits_disabled_but_not_suspended_or_deleted() {
    assert!(
        check_lifecycle_chain(
            LifecycleSeam::Recovery,
            &chain(&[
                ("tenant", "tenant-1", "active"),
                ("project", "proj-off", "disabled"),
            ]),
        )
        .is_ok(),
        "a tenant must be able to re-enable the project it disabled"
    );
    for (raw, expected_code) in [
        ("suspended", "tenancy_suspended"),
        ("deleted", "tenancy_deleted"),
    ] {
        let rejection = check_lifecycle_chain(
            LifecycleSeam::Recovery,
            &chain(&[("tenant", "tenant-1", raw)]),
        )
        .expect_err("a platform lifecycle action is not tenant-reversible");
        assert_eq!(rejection.code(), expected_code, "for status {raw}");
    }
}

/// The Recovery carve-out is REQUEST-time only. Minting new children under a
/// disabled row stays refused, so "recovery" cannot be used to grow the
/// hierarchy that was switched off.
#[test]
fn the_recovery_carve_out_does_not_leak_into_the_attach_seam() {
    let rejection = check_lifecycle_chain(
        LifecycleSeam::Attach,
        &chain(&[("project", "proj-off", "disabled")]),
    )
    .expect_err("a disabled project must still refuse new children");
    assert_eq!(rejection.code(), "inactive_tenancy_reference");
}

/// The rejection names the ROOT cause: when a suspension cascades down the
/// hierarchy the caller is told about the tenant, not sent chasing the leaf.
#[test]
fn the_shallowest_inactive_row_wins_the_rejection() {
    let chain = chain(&[
        ("tenant", "tenant-susp", "suspended"),
        ("project", "proj-susp", "deleted"),
        ("workspace", "ws-susp", "disabled"),
    ]);
    let rejection = check_lifecycle_chain(LifecycleSeam::Request, &chain).unwrap_err();
    assert_eq!(rejection.reference.kind, "tenant");
    assert_eq!(rejection.reference.status, LifecycleStatus::Suspended);
}

/// The attach-time assertion: the live probe minted a brand-new virtual key
/// under a fully suspended chain and got a 201 with a live secret.
#[test]
fn a_suspended_chain_refuses_new_attachments() {
    for raw in ["suspended", "disabled", "deleted"] {
        let chain = chain(&[("tenant", "tenant-1", "active"), ("project", "proj-1", raw)]);
        let rejection = check_lifecycle_chain(LifecycleSeam::Attach, &chain)
            .expect_err("a non-active project must refuse new children");
        assert_eq!(rejection.http_status(), 403, "for {raw}");
        assert_eq!(rejection.code(), "inactive_tenancy_reference", "for {raw}");
        assert!(
            rejection
                .message()
                .contains("cannot be referenced by a new resource"),
            "{}",
            rejection.message()
        );
    }
}

/// The dangerous default, restated at this seam: a legacy row whose `status`
/// column was never written must keep working. If this test ever goes red,
/// shipping #514 revokes every pre-existing tenant.
#[test]
fn absent_or_unknown_status_never_blocks() {
    for raw in ["", "   ", "ACTIVE", "pending_review"] {
        let chain = chain(&[
            ("tenant", "legacy-tenant", raw),
            ("project", "legacy-project", raw),
            ("workspace", "legacy-workspace", raw),
        ]);
        for seam in [
            LifecycleSeam::Request,
            LifecycleSeam::Recovery,
            LifecycleSeam::Attach,
        ] {
            assert!(
                check_lifecycle_chain(seam, &chain).is_ok(),
                "status {raw:?} must not block {seam:?}"
            );
        }
    }
}

// --- the chain WALK ---

/// A scripted hierarchy plus a failure switch. Records every id it was asked
/// for, so the tests can assert not just the verdict but WHICH rows the walk
/// consulted (the landed bug was an unread row, not a wrong comparison) and
/// that a self-consistent triple is not re-read.
#[derive(Default)]
struct FakeRows {
    tenants: HashMap<String, StoredTenantAccount>,
    projects: HashMap<String, StoredProject>,
    workspaces: HashMap<String, StoredWorkspace>,
    fail_on: Option<&'static str>,
    reads: Mutex<Vec<String>>,
}

impl FakeRows {
    fn tenant(mut self, id: &str, status: &str) -> Self {
        self.tenants.insert(
            id.to_string(),
            StoredTenantAccount {
                id: id.to_string(),
                name: id.to_string(),
                slug: id.to_string(),
                status: status.to_string(),
                plan_id: "free".into(),
                created_at_unix: 0,
                updated_at_unix: 0,
            },
        );
        self
    }

    fn project(mut self, id: &str, tenant_id: &str, status: &str) -> Self {
        self.projects.insert(
            id.to_string(),
            StoredProject {
                id: id.to_string(),
                tenant_id: tenant_id.to_string(),
                name: id.to_string(),
                slug: id.to_string(),
                status: status.to_string(),
                created_at_unix: 0,
                updated_at_unix: 0,
            },
        );
        self
    }

    fn workspace(mut self, id: &str, project_id: &str, tenant_id: &str, status: &str) -> Self {
        self.workspaces.insert(
            id.to_string(),
            StoredWorkspace {
                id: id.to_string(),
                project_id: project_id.to_string(),
                tenant_id: tenant_id.to_string(),
                name: id.to_string(),
                slug: id.to_string(),
                environment: "default".into(),
                status: status.to_string(),
                created_at_unix: 0,
                updated_at_unix: 0,
            },
        );
        self
    }

    fn failing(mut self, kind: &'static str) -> Self {
        self.fail_on = Some(kind);
        self
    }

    fn reads(&self) -> Vec<String> {
        self.reads.lock().expect("reads lock").clone()
    }

    fn record(&self, kind: &str, id: &str) -> Result<(), StorageError> {
        self.reads
            .lock()
            .expect("reads lock")
            .push(format!("{kind}:{id}"));
        if self.fail_on == Some(kind) {
            return Err(StorageError::Runtime("control plane unreachable".into()));
        }
        Ok(())
    }
}

#[async_trait]
impl LifecycleRowSource for FakeRows {
    async fn lifecycle_tenant_account(
        &self,
        id: &str,
    ) -> Result<Option<StoredTenantAccount>, StorageError> {
        self.record("tenant", id)?;
        Ok(self.tenants.get(id).cloned())
    }

    async fn lifecycle_project(&self, id: &str) -> Result<Option<StoredProject>, StorageError> {
        self.record("project", id)?;
        Ok(self.projects.get(id).cloned())
    }

    async fn lifecycle_workspace(&self, id: &str) -> Result<Option<StoredWorkspace>, StorageError> {
        self.record("workspace", id)?;
        Ok(self.workspaces.get(id).cloned())
    }
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("test runtime")
        .block_on(future)
}

/// THE regression test for the issue's headline symptom. A native api-key's
/// `organization_id` is optional, so a credential may declare only a
/// `project_id`. The landed implementation pushed only the rows the caller
/// named, so the chain was `[project(active)]` and the suspended tenant above
/// it was never read -- suspension did not stop the key.
#[test]
fn a_project_only_reference_still_reads_the_tenant_above_it() {
    let rows = FakeRows::default()
        .tenant("tenant-susp", "suspended")
        .project("proj-1", "tenant-susp", "active");
    let error = block_on(check_usable_tenancy(
        &rows,
        LifecycleSeam::Request,
        TenancyRefs::new(None, Some("proj-1"), None),
    ))
    .expect_err("the suspended tenant above the declared project must deny");
    let LifecycleGateError::Inactive(rejection) = error else {
        panic!("expected an inactive rejection");
    };
    assert_eq!(rejection.reference.kind, "tenant");
    assert_eq!(rejection.reference.id, "tenant-susp");
    assert!(
        rows.reads().contains(&"tenant:tenant-susp".to_string()),
        "the walk must READ the ancestor it was never told about: {:?}",
        rows.reads()
    );
}

/// Same hole one level deeper: a key that names only a workspace. Both
/// ancestors are backfilled off the workspace row's own `project_id`/
/// `tenant_id` columns.
#[test]
fn a_workspace_only_reference_backfills_project_and_tenant() {
    let rows = FakeRows::default()
        .tenant("tenant-1", "active")
        .project("proj-off", "tenant-1", "suspended")
        .workspace("ws-1", "proj-off", "tenant-1", "active");
    let chain = block_on(resolve_lifecycle_chain(
        &rows,
        TenancyRefs::new(None, None, Some("ws-1")),
    ))
    .expect("resolution must succeed");
    let shape: Vec<_> = chain
        .iter()
        .map(|reference| (reference.kind, reference.id.as_str()))
        .collect();
    assert_eq!(
        shape,
        vec![
            ("tenant", "tenant-1"),
            ("project", "proj-off"),
            ("workspace", "ws-1"),
        ],
        "shallowest-first, ancestors included"
    );
    assert!(block_on(check_usable_tenancy(
        &rows,
        LifecycleSeam::Request,
        TenancyRefs::new(None, None, Some("ws-1")),
    ))
    .is_err());
}

/// The declared ids are not TRUSTED, but they are not discarded either: when a
/// row's own parent disagrees with what the caller declared, both are checked,
/// so neither ordering lets an inactive ancestor be skipped.
#[test]
fn a_declared_tenant_that_disagrees_with_the_row_is_also_checked() {
    let rows = FakeRows::default()
        .tenant("tenant-declared", "suspended")
        .tenant("tenant-real", "active")
        .project("proj-1", "tenant-real", "active");
    let error = block_on(check_usable_tenancy(
        &rows,
        LifecycleSeam::Request,
        TenancyRefs::new(Some("tenant-declared"), Some("proj-1"), None),
    ))
    .expect_err("a suspended declared tenant must still deny");
    let LifecycleGateError::Inactive(rejection) = error else {
        panic!("expected an inactive rejection");
    };
    assert_eq!(rejection.reference.id, "tenant-declared");
}

/// The walk must not turn one authenticated request into six storage reads:
/// a self-consistent triple costs exactly the three rows it names.
#[test]
fn a_self_consistent_triple_is_read_once_per_level() {
    let rows = FakeRows::default()
        .tenant("tenant-1", "active")
        .project("proj-1", "tenant-1", "active")
        .workspace("ws-1", "proj-1", "tenant-1", "active");
    block_on(check_usable_tenancy(
        &rows,
        LifecycleSeam::Request,
        TenancyRefs::new(Some("tenant-1"), Some("proj-1"), Some("ws-1")),
    ))
    .expect("an active chain passes");
    assert_eq!(
        rows.reads(),
        vec![
            "workspace:ws-1".to_string(),
            "project:proj-1".to_string(),
            "tenant:tenant-1".to_string(),
        ]
    );
}

/// Absence is not suspension: a dangling reference resolves to nothing, and a
/// platform-operator credential (no tenancy at all) never reads storage.
#[test]
fn dangling_and_empty_references_resolve_to_an_empty_chain() {
    let rows = FakeRows::default();
    assert!(block_on(resolve_lifecycle_chain(
        &rows,
        TenancyRefs::new(Some("ghost"), Some("ghost"), Some("ghost")),
    ))
    .expect("resolution must succeed")
    .is_empty());

    let rows = FakeRows::default();
    assert!(block_on(resolve_lifecycle_chain(
        &rows,
        TenancyRefs::new(None, Some("   "), None),
    ))
    .expect("resolution must succeed")
    .is_empty());
    assert!(
        rows.reads().is_empty(),
        "an empty triple must not touch storage: {:?}",
        rows.reads()
    );
}

/// Finding 4: the fail-CLOSED claim, held against a real failure rather than a
/// hand-constructed error variant. Replacing the error mapping in
/// `check_usable_tenancy` with `unwrap_or_default()` (fail open) turns each of
/// these red.
#[test]
fn a_storage_failure_is_a_retryable_503_not_a_bypass() {
    for failing_kind in ["tenant", "project", "workspace"] {
        let rows = FakeRows::default()
            .tenant("tenant-1", "active")
            .project("proj-1", "tenant-1", "active")
            .workspace("ws-1", "proj-1", "tenant-1", "active")
            .failing(failing_kind);
        let error = block_on(check_usable_tenancy(
            &rows,
            LifecycleSeam::Request,
            TenancyRefs::new(Some("tenant-1"), Some("proj-1"), Some("ws-1")),
        ))
        .expect_err("a control-plane read failure must not resolve to 'active'");
        assert_eq!(error.http_status(), 503, "for failing {failing_kind}");
        assert_eq!(error.code(), "lifecycle_status_unavailable");
        assert!(
            error.message().contains("control plane unreachable"),
            "{}",
            error.message()
        );
    }
}

/// The same fail-closed rule at the ATTACH seam: a flapping control plane must
/// not become a licence to mint fresh credentials under an unknown chain.
#[test]
fn a_storage_failure_also_refuses_new_attachments() {
    let rows = FakeRows::default()
        .tenant("tenant-1", "active")
        .failing("tenant");
    let error = block_on(check_usable_tenancy(
        &rows,
        LifecycleSeam::Attach,
        TenancyRefs::tenant("tenant-1"),
    ))
    .expect_err("a control-plane read failure must not permit an attach");
    assert_eq!(error.http_status(), 503);
}
