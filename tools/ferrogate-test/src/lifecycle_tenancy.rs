// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-29
// description: Tenancy lifecycle end-to-end coverage for the FerroGate test harness.

use crate::{
    assertions::list_contains,
    cli::SupabaseLiveRestartArgs,
    constants::{ADMIN_AUTH, JSON_CONTENT},
    storage::{
        supabase_live_tls_mode, ControlPlaneRestartStorage, PostgresRestartTls, TursoRestartHarness,
    },
    supabase_schema::{LiveSupabaseScenario, LiveSupabaseSchema},
};
use anyhow::{bail, Context, Result};
use serde_json::json;

pub(crate) fn run_lifecycle_tenancy_supabase(args: &SupabaseLiveRestartArgs) -> Result<()> {
    let dsn = args.supabase_dsn.trim();
    if dsn.is_empty() {
        bail!("--supabase-dsn must not be empty");
    }

    let mut schema = LiveSupabaseSchema::create(args, LiveSupabaseScenario::LifecycleTenancy)?;
    let storage = ControlPlaneRestartStorage::Supabase {
        dsn,
        tls: PostgresRestartTls {
            mode: supabase_live_tls_mode(&args.tls_mode)?,
            ca_cert_path: args.tls_ca_cert_path.as_deref(),
        },
        schema: schema.name(),
        live: true,
    };
    let fixture = LiveLifecycleFixture::new(schema.run_id());

    {
        let case = TursoRestartHarness::start(&args.local.ferrogate_bin, storage, false, false)?;
        case.expect_storage_status()?;
        fixture.bootstrap(&case)?;
        fixture.expect_models(&case, &fixture.client_auth())?;

        fixture.set_tenant_status(&case, "suspended")?;
        fixture.expect_models_rejected(&case, &fixture.client_auth(), "tenancy_suspended")?;
        fixture.expect_suspended_attach_rejected(&case)?;

        fixture.set_tenant_status(&case, "active")?;
        fixture.expect_models(&case, &fixture.client_auth())?;
        let fresh_secret = fixture.create_fresh_key(&case)?;
        fixture.expect_models(&case, &format!("Authorization: Bearer {fresh_secret}"))?;
    }

    schema.finish()?;
    println!("lifecycle-tenancy-supabase scenario passed");
    Ok(())
}

struct LiveLifecycleFixture {
    tenant_id: String,
    tenant_slug: String,
    project_id: String,
    workspace_id: String,
    client_id: String,
    client_secret: String,
}

impl LiveLifecycleFixture {
    fn new(run_id: &str) -> Self {
        let slug = run_id.replace('_', "-");
        Self {
            tenant_id: format!("life-tenant-{run_id}"),
            tenant_slug: format!("life-tenant-{slug}"),
            project_id: format!("life-project-{run_id}"),
            workspace_id: format!("life-workspace-{run_id}"),
            client_id: format!("life-client-{run_id}"),
            client_secret: format!("life-client-secret-{run_id}"),
        }
    }

    fn client_auth(&self) -> String {
        format!("Authorization: Bearer {}", self.client_secret)
    }

    fn bootstrap(&self, case: &TursoRestartHarness) -> Result<()> {
        case.expect_json(
            "POST",
            "/admin/v1/tenant-accounts",
            &[ADMIN_AUTH, JSON_CONTENT],
            &json!({
                "id": self.tenant_id,
                "name": "Lifecycle live tenant",
                "slug": self.tenant_slug,
            })
            .to_string(),
            201,
            |body| {
                assert_eq!(body["tenant"]["id"], self.tenant_id);
                assert_eq!(body["tenant"]["status"], "active");
                Ok(())
            },
        )?;
        case.expect_json(
            "POST",
            "/admin/v1/projects",
            &[ADMIN_AUTH, JSON_CONTENT],
            &json!({
                "id": self.project_id,
                "tenant_id": self.tenant_id,
                "name": "Lifecycle live project",
                "slug": self.project_id,
            })
            .to_string(),
            201,
            |body| {
                assert_eq!(body["project"]["id"], self.project_id);
                assert_eq!(body["project"]["status"], "active");
                Ok(())
            },
        )?;
        case.expect_json(
            "POST",
            "/admin/v1/workspaces",
            &[ADMIN_AUTH, JSON_CONTENT],
            &json!({
                "id": self.workspace_id,
                "project_id": self.project_id,
                "name": "Lifecycle live workspace",
                "slug": self.workspace_id,
            })
            .to_string(),
            201,
            |body| {
                assert_eq!(body["workspace"]["id"], self.workspace_id);
                assert_eq!(body["workspace"]["status"], "active");
                Ok(())
            },
        )?;
        case.expect_json(
            "POST",
            "/admin/v1/api-keys",
            &[ADMIN_AUTH, JSON_CONTENT],
            &json!({
                "id": self.client_id,
                "name": "Lifecycle live client",
                "key": self.client_secret,
                "organization_id": self.tenant_id,
                "project_id": self.project_id,
                "scopes": ["models.read"],
                "allowed_models": ["fast-chat"],
            })
            .to_string(),
            201,
            |body| {
                assert_eq!(body["key"]["id"], self.client_id);
                Ok(())
            },
        )
    }

    fn set_tenant_status(&self, case: &TursoRestartHarness, status: &str) -> Result<()> {
        case.expect_json(
            "PUT",
            &format!("/admin/v1/tenant-accounts/{}", self.tenant_id),
            &[ADMIN_AUTH, JSON_CONTENT],
            &json!({ "status": status }).to_string(),
            200,
            |body| {
                assert_eq!(body["tenant"]["status"], status);
                Ok(())
            },
        )
    }

    fn expect_models(&self, case: &TursoRestartHarness, auth: &str) -> Result<()> {
        case.expect_json("GET", "/v1/models", &[auth], "", 200, |body| {
            assert!(
                list_contains(&body, "id", "fast-chat"),
                "fast-chat model was not listed: {body}"
            );
            Ok(())
        })
    }

    fn expect_models_rejected(
        &self,
        case: &TursoRestartHarness,
        auth: &str,
        code: &str,
    ) -> Result<()> {
        case.expect_json("GET", "/v1/models", &[auth], "", 403, |body| {
            assert_eq!(body["error"]["code"], code);
            Ok(())
        })
    }

    fn expect_suspended_attach_rejected(&self, case: &TursoRestartHarness) -> Result<()> {
        let blocked_project = format!("{}-blocked-project", self.tenant_id);
        case.expect_json(
            "POST",
            "/admin/v1/projects",
            &[ADMIN_AUTH, JSON_CONTENT],
            &json!({
                "id": blocked_project,
                "tenant_id": self.tenant_id,
                "name": "Blocked lifecycle project",
                "slug": blocked_project,
            })
            .to_string(),
            403,
            |body| {
                assert_eq!(body["error"]["code"], "inactive_tenancy_reference");
                Ok(())
            },
        )?;

        let blocked_key = format!("{}-blocked-key", self.client_id);
        case.expect_json(
            "POST",
            "/admin/v1/api-keys",
            &[ADMIN_AUTH, JSON_CONTENT],
            &json!({
                "id": blocked_key,
                "name": "Blocked lifecycle key",
                "key": format!("{blocked_key}-secret"),
                "organization_id": self.tenant_id,
                "project_id": self.project_id,
                "scopes": ["models.read"],
                "allowed_models": ["fast-chat"],
            })
            .to_string(),
            403,
            |body| {
                assert_eq!(body["error"]["code"], "inactive_tenancy_reference");
                Ok(())
            },
        )
    }

    fn create_fresh_key(&self, case: &TursoRestartHarness) -> Result<String> {
        let fresh_id = format!("{}-fresh", self.client_id);
        let fresh_secret = format!("{fresh_id}-secret");
        case.expect_json(
            "POST",
            "/admin/v1/api-keys",
            &[ADMIN_AUTH, JSON_CONTENT],
            &json!({
                "id": fresh_id,
                "name": "Lifecycle fresh client",
                "key": fresh_secret,
                "organization_id": self.tenant_id,
                "project_id": self.project_id,
                "scopes": ["models.read"],
                "allowed_models": ["fast-chat"],
            })
            .to_string(),
            201,
            |body| {
                assert_eq!(body["key"]["id"], fresh_id);
                Ok(())
            },
        )
        .context("create fresh lifecycle key after tenant reactivation")?;
        Ok(fresh_secret)
    }
}
