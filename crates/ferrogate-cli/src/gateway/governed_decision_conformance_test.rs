// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Token4AI Cloud, FerroGate AI Gateway, Runner A of the #470
// governed-decision conformance suite: drives the committed
// tests/fixtures/governed-decisions corpus through the real admission seam
// (decide_ai_request) and enforces the error-vocabulary coverage gate.

//! Runner A -- the authority (Rust, in-process).
//!
//! Loads every fixture in `tests/fixtures/governed-decisions/`, materialises an
//! [`AppState`] from the fixture's `world`, drives
//! [`super::chat::decide_ai_request`] -- the *production* admission seam, not a
//! replica -- and asserts the canonical serialisation of the resulting
//! [`GovernedDecisionRecord`] is byte-identical to the committed golden.
//!
//! It also enforces the two gates that stop the corpus from becoming
//! decoration:
//!
//! * **Coverage.** Every vocabulary entry marked
//!   [`FixtureCoverage::Required`] must appear as the expected code of at
//!   least one fixture. Adding a reproducible governed outcome therefore forces
//!   a fixture before it can ship.
//! * **Directionality.** Each fixture also declares what the veto-only Worker
//!   shell (`docs/cloudflare-data-plane-decision.md` §6) is allowed to answer.
//!   That declaration is checked here against
//!   [`directional_conformance`], so the corpus cannot contain a Worker
//!   expectation that would itself be a divergence. Runner B
//!   (`workers/gateway-front`) then checks that the Worker actually produces
//!   it.

use std::{collections::BTreeSet, fs, path::PathBuf};

use http::{HeaderMap, HeaderName, HeaderValue};
use serde::Deserialize;

use super::{
    chat::{decide_ai_request, AiEndpoint, AiRequestBody},
    governed_decision::{
        directional_conformance, governed_error_code, FixtureCoverage, GovernedDecisionRecord,
        GOVERNED_DECISION_SCHEMA, GOVERNED_ERROR_VOCABULARY,
    },
    ProxyContext,
};
use crate::state::SharedAppState;
use ferrogate_config::Config;

fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(future)
}

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/governed-decisions")
        .canonicalize()
        .expect("the governed-decision corpus directory must exist")
}

#[derive(Debug, Deserialize)]
struct Fixture {
    id: String,
    schema: u32,
    /// Why this case exists. Asserted non-trivial so a fixture cannot be
    /// added without saying what governed behaviour it pins.
    description: String,
    world: FixtureWorld,
    request: FixtureRequest,
    expect: GovernedDecisionRecord,
    worker_shell: FixtureWorkerShell,
}

#[derive(Debug, Deserialize)]
struct FixtureWorld {
    /// The gateway config, deserialised straight into the real [`Config`] --
    /// the fixture cannot describe a world the product cannot be configured
    /// into.
    config: serde_json::Value,
    #[serde(default)]
    draining: bool,
    #[serde(default)]
    wallets: Vec<FixtureWallet>,
    #[serde(default)]
    quota_policies: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct FixtureWallet {
    tenant_id: String,
    /// Decimal string, parsed as an integer -- amounts are never floats here
    /// (the #469 discipline applied to the fixture format itself).
    balance_credits: String,
}

#[derive(Debug, Deserialize)]
struct FixtureRequest {
    /// `chat.completions` or `responses`.
    endpoint: String,
    #[serde(default)]
    headers: std::collections::BTreeMap<String, String>,
    /// Header values that are legal HTTP bytes but not UTF-8. JSON cannot
    /// carry them as strings, and the gateway has governed outcomes that only
    /// fire on exactly that input, so they are spelled out byte by byte.
    #[serde(default)]
    headers_bytes: std::collections::BTreeMap<String, Vec<u8>>,
    /// Parsed JSON body. Mutually exclusive with `body_raw`.
    #[serde(default)]
    body: Option<serde_json::Value>,
    /// Raw bytes, for the cases where the body is *not* valid JSON.
    #[serde(default)]
    body_raw: Option<String>,
    /// The Session-side body read hit the configured cap. Modelled as a fact
    /// because reading the body is I/O and the decision never touches the
    /// socket.
    #[serde(default)]
    body_over_limit: bool,
    #[serde(default)]
    body_over_limit_max_bytes: usize,
    now_unix: u64,
}

#[derive(Debug, Deserialize)]
struct FixtureWorkerShell {
    /// Revoked key ids / suspended tenants the operator has pushed to the
    /// edge. The only input the shell is allowed to make a call on.
    #[serde(default)]
    deny_list: Vec<String>,
    expect: GovernedDecisionRecord,
}

fn load_fixtures() -> Vec<(String, Fixture)> {
    let mut paths: Vec<PathBuf> = fs::read_dir(corpus_dir())
        .expect("corpus directory must be readable")
        .map(|entry| entry.expect("corpus entry must be readable").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect();
    paths.sort();
    assert!(
        !paths.is_empty(),
        "the governed-decision corpus is empty; the coverage gate would pass vacuously"
    );
    paths
        .into_iter()
        .map(|path| {
            let name = path
                .file_name()
                .expect("fixture has a file name")
                .to_string_lossy()
                .into_owned();
            let raw = fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("cannot read fixture {name}: {error}"));
            let fixture: Fixture = serde_json::from_str(&raw)
                .unwrap_or_else(|error| panic!("cannot parse fixture {name}: {error}"));
            (name, fixture)
        })
        .collect()
}

/// Materialises the fixture's world and drives the real admission seam.
fn decide(fixture: &Fixture) -> GovernedDecisionRecord {
    let config: Config =
        serde_json::from_value(fixture.world.config.clone()).unwrap_or_else(|error| {
            panic!(
                "{}: world.config is not a valid Config: {error}",
                fixture.id
            )
        });
    let shared = SharedAppState::with_source_path(config, None);
    if fixture.world.draining {
        shared.set_drain(true);
    }
    let state = shared.current();

    for wallet in &fixture.world.wallets {
        let balance = wallet
            .balance_credits
            .parse::<i64>()
            .unwrap_or_else(|error| {
                panic!(
                    "{}: wallet balance {:?} must be a decimal integer string: {error}",
                    fixture.id, wallet.balance_credits
                )
            });
        block_on(state.upsert_wallet(ferrogate_storage::StoredWallet {
            id: wallet.tenant_id.clone(),
            tenant_id: wallet.tenant_id.clone(),
            balance_credits: balance,
            auto_recharge_threshold_credits: None,
            auto_recharge_amount_credits: None,
            dunning: false,
            created_at_unix: 1,
            updated_at_unix: 1,
        }))
        .expect("seeding a wallet must succeed");
    }
    for policy in &fixture.world.quota_policies {
        let policy: ferrogate_storage::StoredQuotaPolicy = serde_json::from_value(policy.clone())
            .unwrap_or_else(|error| {
                panic!(
                    "{}: quota policy is not a StoredQuotaPolicy: {error}",
                    fixture.id
                )
            });
        block_on(state.upsert_quota_policy(policy)).expect("seeding a quota policy must succeed");
    }

    let endpoint = match fixture.request.endpoint.as_str() {
        "chat.completions" => AiEndpoint::ChatCompletions,
        "responses" => AiEndpoint::Responses,
        other => panic!("{}: unknown endpoint {other:?}", fixture.id),
    };
    let mut headers = HeaderMap::new();
    for (name, value) in &fixture.request.headers {
        headers.insert(
            HeaderName::from_bytes(name.as_bytes()).expect("fixture header name is valid"),
            HeaderValue::from_str(value).expect("fixture header value is valid"),
        );
    }
    for (name, value) in &fixture.request.headers_bytes {
        headers.insert(
            HeaderName::from_bytes(name.as_bytes()).expect("fixture header name is valid"),
            HeaderValue::from_bytes(value).expect("fixture header bytes are legal header bytes"),
        );
    }
    let body = if fixture.request.body_over_limit {
        AiRequestBody::TooLarge {
            max_bytes: fixture.request.body_over_limit_max_bytes,
        }
    } else {
        let bytes = match (&fixture.request.body, &fixture.request.body_raw) {
            (Some(_), Some(_)) => {
                panic!("{}: body and body_raw are mutually exclusive", fixture.id)
            }
            (Some(body), None) => serde_json::to_vec(body).expect("fixture body serialises"),
            (None, Some(raw)) => raw.clone().into_bytes(),
            (None, None) => Vec::new(),
        };
        AiRequestBody::Read(bytes.into())
    };
    let ctx = ProxyContext {
        request_id: format!("conformance-{}", fixture.id),
        ..ProxyContext::default()
    };

    match block_on(decide_ai_request(
        &state,
        &headers,
        body,
        endpoint,
        &ctx,
        fixture.request.now_unix,
    )) {
        Ok(_plan) => GovernedDecisionRecord::admitted(),
        Err(decision) => decision.record,
    }
}

#[test]
fn every_fixture_matches_the_authority_byte_for_byte() {
    for (name, fixture) in load_fixtures() {
        assert_eq!(
            fixture.schema, GOVERNED_DECISION_SCHEMA,
            "{name}: fixture was written against schema {} but the canonical form is now {}",
            fixture.schema, GOVERNED_DECISION_SCHEMA
        );
        assert!(
            fixture.description.len() > 30,
            "{name}: the description must say what governed behaviour this pins"
        );
        let actual = decide(&fixture);
        assert_eq!(
            actual.canonical_json(),
            fixture.expect.canonical_json(),
            "{name} ({}) diverged from its golden decision",
            fixture.id
        );
    }
}

#[test]
fn every_fixture_expectation_uses_the_shared_vocabulary() {
    for (name, fixture) in load_fixtures() {
        if let Some(code) = fixture.expect.code.as_deref() {
            assert!(
                governed_error_code(code).is_some(),
                "{name}: expected code {code:?} is not in GOVERNED_ERROR_VOCABULARY"
            );
        }
        if let Some(code) = fixture.worker_shell.expect.code.as_deref() {
            assert!(
                governed_error_code(code).is_some(),
                "{name}: the Worker-shell expectation uses {code:?}, which is not in the \
                 shared vocabulary"
            );
        }
    }
}

#[test]
fn every_required_code_has_a_fixture() {
    let covered: BTreeSet<String> = load_fixtures()
        .into_iter()
        .filter_map(|(_, fixture)| fixture.expect.code)
        .collect();
    let missing: Vec<&str> = GOVERNED_ERROR_VOCABULARY
        .iter()
        .filter(|entry| entry.coverage.is_required())
        .map(|entry| entry.code)
        .filter(|code| !covered.contains(*code))
        .collect();
    assert!(
        missing.is_empty(),
        "these governed codes are declared reproducible from a fixture world but have no \
         fixture: {missing:?}. Either add tests/fixtures/governed-decisions/<case>.json, or \
         change the code's FixtureCoverage and say why it cannot be reproduced."
    );
}

#[test]
fn the_worker_shell_expectation_is_directionally_legal_for_every_fixture() {
    for (name, fixture) in load_fixtures() {
        directional_conformance(&fixture.expect, &fixture.worker_shell.expect).unwrap_or_else(
            |reason| {
                panic!("{name}: the declared Worker-shell answer is itself a divergence: {reason}")
            },
        );
        // A shell deny may only be justified by a host-independent,
        // fail-closed fact. The deny list is the one input it is allowed to
        // consult, so a fixture that expects a deny without one is either
        // wrong or is smuggling a governed decision into the edge.
        if fixture.worker_shell.expect.code.is_some()
            && fixture.worker_shell.deny_list.is_empty()
            && !SHELL_HOST_INDEPENDENT_CODES.contains(
                &fixture
                    .worker_shell
                    .expect
                    .code
                    .as_deref()
                    .unwrap_or_default(),
            )
        {
            panic!(
                "{name}: the Worker shell denies with {:?} but consults no deny list and the \
                 code is not host-independent; that is a governed decision at the edge",
                fixture.worker_shell.expect.code
            );
        }
    }
}

/// The only codes a veto-only shell may reach on its own, per the §6 contract:
/// facts that do not depend on any control-plane state the origin owns.
///
/// Deliberately excludes `invalid_request`. A typed-parse verdict is *not*
/// host-independent -- the shell would need the origin's request schema to
/// agree with it -- so letting the edge author one would reintroduce exactly
/// the divergence the shell contract exists to prevent, in the direction that
/// produces false rejections.
const SHELL_HOST_INDEPENDENT_CODES: &[&str] =
    &["missing_api_key", "payload_too_large", "invalid_json"];

#[test]
fn the_corpus_covers_the_mandatory_money_cases() {
    // §8a: money cases are mandatory, not optional. These are the
    // admission-stage members of that set -- the wallet, the monthly budget,
    // the per-key token budget and the per-minute request budget are all
    // decisions that cost or save the tenant money, and #476 is the record of
    // what happens when two hosts make one of them with different rigour.
    let covered: BTreeSet<String> = load_fixtures()
        .into_iter()
        .filter_map(|(_, fixture)| fixture.expect.code)
        .collect();
    for money_case in [
        "wallet_balance_exhausted",
        "monthly_budget_exceeded",
        "token_budget_exceeded",
        "rate_limit_exceeded",
        "quota_scope_disabled",
    ] {
        assert!(
            covered.contains(money_case),
            "the corpus has no fixture for the mandatory money case {money_case:?}"
        );
    }
}

#[test]
fn pending_codes_are_visible_rather_than_silent() {
    // The corpus is allowed to be incomplete; it is not allowed to be
    // *quietly* incomplete. Everything not fixtured must be enumerated with a
    // reason, and this test is what makes that enumeration a gate.
    let pending: Vec<(&str, &str)> = GOVERNED_ERROR_VOCABULARY
        .iter()
        .filter(|entry| !entry.coverage.is_required())
        .filter(|entry| !matches!(entry.coverage, FixtureCoverage::NotOnAiPath(_)))
        .map(|entry| (entry.code, entry.coverage.reason().unwrap_or_default()))
        .collect();
    for (code, reason) in &pending {
        assert!(
            !reason.is_empty(),
            "{code} is pending with no stated reason"
        );
    }
    // Pinning the count keeps the pending set from growing unnoticed: a new
    // unfixtured governed outcome has to move this number, in a reviewable
    // diff, on purpose.
    assert_eq!(
        pending.len(),
        17,
        "the set of governed codes without a fixture changed: {pending:#?}"
    );
}
