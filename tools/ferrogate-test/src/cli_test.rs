// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: CLI tests for live Supabase schema isolation controls.

use super::*;

#[test]
fn live_supabase_schema_retention_is_disabled_by_default() {
    let cli = Cli::try_parse_from([
        "ferrogate-test",
        "supabase-live-smoke",
        "--supabase-dsn",
        "postgresql://unused",
    ])
    .unwrap();
    let Commands::SupabaseLiveSmoke(args) = cli.command else {
        panic!("expected supabase-live-smoke command");
    };
    assert!(!args.keep_supabase_schema);
}

#[test]
fn live_supabase_schema_retention_requires_explicit_flag() {
    let cli = Cli::try_parse_from([
        "ferrogate-test",
        "component-compliance-supabase",
        "--supabase-dsn",
        "postgresql://unused",
        "--keep-supabase-schema",
    ])
    .unwrap();
    let Commands::ComponentComplianceSupabase(args) = cli.command else {
        panic!("expected component-compliance-supabase command");
    };
    assert!(args.keep_supabase_schema);
}

#[test]
fn the_x402_paid_egress_chain_is_a_deterministic_local_scenario() {
    let cli = Cli::try_parse_from(["ferrogate-test", "x402-paid-egress-chain"]).unwrap();

    // #354's Verification section promises this command by name. It takes only a
    // ferrogate binary: no DSN, no image, nothing opt-in -- so a gate run cannot
    // "pass" it by silently skipping an unconfigured dependency.
    let Commands::X402PaidEgressChain(args) = cli.command else {
        panic!("expected x402-paid-egress-chain command");
    };
    assert_eq!(args.ferrogate_bin, PathBuf::from("target/debug/ferrogate"));
}

#[test]
fn target_capability_supabase_uses_live_schema_controls() {
    let cli = Cli::try_parse_from([
        "ferrogate-test",
        "target-capability-supabase",
        "--supabase-dsn",
        "postgresql://unused",
        "--keep-supabase-schema",
    ])
    .unwrap();
    let Commands::TargetCapabilitySupabase(args) = cli.command else {
        panic!("expected target-capability-supabase command");
    };
    assert!(args.keep_supabase_schema);
}
