// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use anyhow::Result;

mod assertions;
mod cli;
mod constants;
mod docker;
mod fixtures;
mod http;
mod local;
mod mocks;
mod scenarios;
mod storage;

use docker::{run_all_docker_scenarios, run_docker_scenario};
use scenarios::{
    run_admin_api, run_auth_api, run_function_egress_api, run_gateway_api,
    run_gateway_billing_chain, run_gateway_external_auth_api, run_gateway_third_party_auth_api,
};
use storage::{
    run_mysql_restart, run_mysql_tls_restart, run_postgres_restart, run_postgres_tls_restart,
    run_supabase_live_restart, run_supabase_live_smoke, run_supabase_live_token4ai_provider,
    run_supabase_migration, run_supabase_restart,
};

fn main() -> Result<()> {
    cli::run(cli::Dispatch {
        admin: run_admin_api,
        auth: run_auth_api,
        gateway: run_gateway_api,
        gateway_billing_chain: run_gateway_billing_chain,
        function_egress: run_function_egress_api,
        supabase_restart: run_supabase_restart,
        supabase_live_smoke: run_supabase_live_smoke,
        supabase_live_restart: run_supabase_live_restart,
        supabase_live_token4ai_provider: run_supabase_live_token4ai_provider,
        supabase_migration: run_supabase_migration,
        postgres_restart: run_postgres_restart,
        postgres_tls_restart: run_postgres_tls_restart,
        mysql_restart: run_mysql_restart,
        mysql_tls_restart: run_mysql_tls_restart,
        docker: run_docker_scenario,
        run_all_admin_auth_gateway: |local, auth, include_docker, image| {
            run_admin_api(local)?;
            run_auth_api(auth)?;
            run_gateway_external_auth_api(local, auth)?;
            run_gateway_third_party_auth_api(local)?;
            run_gateway_api(local)?;
            if include_docker {
                run_all_docker_scenarios(image)?;
            }
            Ok(())
        },
        ci: |local, auth| {
            run_admin_api(local)?;
            run_auth_api(auth)?;
            run_gateway_external_auth_api(local, auth)?;
            run_gateway_third_party_auth_api(local)?;
            run_gateway_api(local)?;
            run_gateway_billing_chain(local)?;
            run_function_egress_api(local)?;
            run_supabase_migration(local)?;
            run_supabase_restart(local)?;
            run_postgres_restart(local)?;
            run_postgres_tls_restart(local)
        },
    })
}
