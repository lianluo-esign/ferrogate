// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use anyhow::Result;

mod api_contract;
mod assertions;
mod cli;
mod compliance;
mod constants;
mod docker;
mod fixtures;
mod guardrails;
mod http;
mod local;
mod mcp_identity;
mod mocks;
mod provider_compliance;
mod scenarios;
mod storage;
mod supabase_schema;
mod target_capability;

use api_contract::run_api_contract;
use compliance::{run_component_compliance, run_component_compliance_supabase};
use docker::{run_all_docker_scenarios, run_docker_scenario};
use guardrails::run_guardrail_supabase;
use mcp_identity::run_mcp_identity_supabase;
use scenarios::{
    run_admin_api, run_auth_api, run_function_egress_api, run_gateway_api,
    run_gateway_billing_chain, run_gateway_external_auth_api, run_gateway_third_party_auth_api,
};
use storage::{
    run_postgres_restart, run_postgres_tls_restart, run_supabase_live_restart,
    run_supabase_live_smoke, run_supabase_live_token4ai_provider, run_supabase_migration,
    run_supabase_restart,
};
use target_capability::run_target_capability_supabase;

fn main() -> Result<()> {
    cli::run(cli::Dispatch {
        admin: run_admin_api,
        auth: run_auth_api,
        gateway: run_gateway_api,
        api_contract: run_api_contract,
        component_compliance: run_component_compliance,
        component_compliance_supabase: run_component_compliance_supabase,
        gateway_billing_chain: run_gateway_billing_chain,
        function_egress: run_function_egress_api,
        supabase_restart: run_supabase_restart,
        supabase_live_smoke: run_supabase_live_smoke,
        supabase_live_restart: run_supabase_live_restart,
        supabase_live_token4ai_provider: run_supabase_live_token4ai_provider,
        guardrail_supabase: run_guardrail_supabase,
        mcp_identity_supabase: run_mcp_identity_supabase,
        target_capability_supabase: run_target_capability_supabase,
        supabase_migration: run_supabase_migration,
        postgres_restart: run_postgres_restart,
        postgres_tls_restart: run_postgres_tls_restart,
        docker: run_docker_scenario,
        run_all_admin_auth_gateway: |local, auth, include_docker, image| {
            run_admin_api(local)?;
            run_auth_api(auth)?;
            run_gateway_external_auth_api(local, auth)?;
            run_gateway_third_party_auth_api(local)?;
            run_gateway_api(local)?;
            run_component_compliance(local)?;
            if include_docker {
                run_all_docker_scenarios(image)?;
            }
            Ok(())
        },
        ci: |local, auth| {
            run_api_contract(local)?;
            run_component_compliance(local)?;
            run_admin_api(local)?;
            run_auth_api(auth)?;
            run_gateway_external_auth_api(local, auth)?;
            run_gateway_third_party_auth_api(local)?;
            run_gateway_api(local)?;
            run_function_egress_api(local)?;
            run_supabase_migration(local)?;
            run_supabase_restart(local)?;
            run_postgres_restart(local)?;
            run_postgres_tls_restart(local)
        },
    })
}
