// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use anyhow::Result;

mod admin_console_roles;
mod agent_jobs;
mod api_contract;
mod assertions;
/// #368: the size+checksum-bound presigned staging upload path.
mod asset_presign;
mod asset_registry;
mod cli;
/// #505: the CLI mutation decision-receipt E2E (dry-run issues nothing; the
/// receipt's own rollback pointer reverses a guardrail policy revision).
mod cli_mutation_receipt;
mod cloudflare_secret;
mod compliance;
mod constants;
mod docker;
mod fixtures;
mod function_egress_cloudflare;
mod guardrails;
mod http;
mod local;
mod managed_action_project;
mod mcp_identity;
mod mocks;
/// #352: durable x402 payment attempts + their wallet-hold links inside the
/// `*-restart` scenarios' verified set.
mod payment_attempt_restart;
mod provider_compliance;
mod scenarios;
mod static_site;
mod storage;
mod supabase_schema;
mod target_capability;
mod worker_release;
mod workers_ai_guardrail;
/// #354: the narrow cross-component managed paid-egress chain command --
/// gateway policy decision, deterministic merchant double, durable attempt/hold
/// ledger, re-drive and reconcile.
mod x402_paid_egress_chain;
/// #351: the component-compliance closure for the typed Solana x402 spend
/// policy (operator config -> effective policy -> runtime decision).
mod x402_spend_policy;

use admin_console_roles::run_admin_console_roles_supabase;
use agent_jobs::run_agent_jobs_api;
use api_contract::run_api_contract;
use asset_presign::{run_asset_buffer_admission, run_asset_presign_api};
use asset_registry::run_asset_registry_api;
use cli_mutation_receipt::run_cli_mutation_receipt;
use cloudflare_secret::run_cloudflare_secret_api;
use compliance::{run_component_compliance, run_component_compliance_supabase};
use docker::{run_all_docker_scenarios, run_docker_scenario};
use function_egress_cloudflare::run_function_egress_cloudflare_api;
use guardrails::run_guardrail_supabase;
use managed_action_project::run_managed_action_project;
use mcp_identity::run_mcp_identity_supabase;
use scenarios::{
    run_admin_api, run_auth_api, run_function_egress_api, run_gateway_api,
    run_gateway_billing_chain, run_gateway_external_auth_api, run_gateway_third_party_auth_api,
};
use static_site::run_static_site_api;
use storage::{
    run_postgres_restart, run_postgres_tls_restart, run_supabase_live_restart,
    run_supabase_live_smoke, run_supabase_live_token4ai_provider, run_supabase_migration,
    run_supabase_restart,
};
use target_capability::run_target_capability_supabase;
use worker_release::run_worker_release;
use workers_ai_guardrail::run_workers_ai_llama_guard;
use x402_paid_egress_chain::run_x402_paid_egress_chain;

fn main() -> Result<()> {
    cli::run(cli::Dispatch {
        admin: run_admin_api,
        auth: run_auth_api,
        gateway: run_gateway_api,
        cloudflare_secret: run_cloudflare_secret_api,
        api_contract: run_api_contract,
        component_compliance: run_component_compliance,
        component_compliance_supabase: run_component_compliance_supabase,
        gateway_billing_chain: run_gateway_billing_chain,
        x402_paid_egress_chain: run_x402_paid_egress_chain,
        function_egress: run_function_egress_api,
        function_egress_cloudflare: run_function_egress_cloudflare_api,
        static_site: run_static_site_api,
        asset_presign: run_asset_presign_api,
        asset_buffer_admission: run_asset_buffer_admission,
        asset_registry: run_asset_registry_api,
        agent_jobs: run_agent_jobs_api,
        managed_action_project: run_managed_action_project,
        cli_mutation_receipt: run_cli_mutation_receipt,
        supabase_restart: run_supabase_restart,
        supabase_live_smoke: run_supabase_live_smoke,
        supabase_live_restart: run_supabase_live_restart,
        supabase_live_token4ai_provider: run_supabase_live_token4ai_provider,
        guardrail_supabase: run_guardrail_supabase,
        guardrail_workers_ai_llama_guard: run_workers_ai_llama_guard,
        mcp_identity_supabase: run_mcp_identity_supabase,
        target_capability_supabase: run_target_capability_supabase,
        admin_console_roles_supabase: run_admin_console_roles_supabase,
        supabase_migration: run_supabase_migration,
        postgres_restart: run_postgres_restart,
        postgres_tls_restart: run_postgres_tls_restart,
        worker_release: run_worker_release,
        docker: run_docker_scenario,
        run_all_admin_auth_gateway: |local, auth, include_docker, image| {
            run_admin_api(local)?;
            run_auth_api(auth)?;
            run_gateway_external_auth_api(local, auth)?;
            run_gateway_third_party_auth_api(local)?;
            run_gateway_api(local)?;
            run_cloudflare_secret_api(local)?;
            run_component_compliance(local)?;
            run_workers_ai_llama_guard(local)?;
            if include_docker {
                run_all_docker_scenarios(image)?;
            }
            Ok(())
        },
        ci: |local, auth| {
            run_worker_release()?;
            run_api_contract(local)?;
            run_component_compliance(local)?;
            run_admin_api(local)?;
            run_auth_api(auth)?;
            run_gateway_external_auth_api(local, auth)?;
            run_gateway_third_party_auth_api(local)?;
            run_gateway_api(local)?;
            run_cloudflare_secret_api(local)?;
            run_function_egress_api(local)?;
            run_function_egress_cloudflare_api(local)?;
            run_static_site_api(local)?;
            run_asset_presign_api(local)?;
            run_asset_buffer_admission(local)?;
            run_asset_registry_api(local)?;
            run_agent_jobs_api(local)?;
            run_managed_action_project(local)?;
            // #505: the CLI's own governed-output contract. Docker-free and
            // deterministic (one local gateway, the shipped `ferrogate` binary
            // as its own client), so it belongs in the always-run set — a
            // mutating verb that stopped returning a receipt, or a `--dry-run`
            // that started reaching the server, must fail CI rather than wait
            // for someone to type the command.
            run_cli_mutation_receipt(local)?;
            // The #354 cross-component paid-egress chain. Deterministic (fixed
            // clock, local origin/facilitator double, no Docker, no network),
            // so it belongs in the always-run set rather than being a command
            // only a human remembers to type.
            run_x402_paid_egress_chain(local)?;
            run_workers_ai_llama_guard(local)?;
            run_supabase_migration(local)?;
            run_supabase_restart(local)?;
            run_postgres_restart(local)?;
            run_postgres_tls_restart(local)
        },
    })
}
