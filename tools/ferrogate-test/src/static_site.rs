// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Docker-free E2E coverage for the static-site publish/serve/per-file family (#441).

//! End-to-end proof of the static-site asset family over a real gateway
//! (#441, gate-owned harness growth): a #397 zip bundle is published through
//! the REAL `PUT /v1/assets/static_site/{site}/{version}` surface (per-file
//! objects under `__site_file__:{version}:{path}` + a serving channel), the
//! site serves from `/sites/{tenant}/{site}/…`, and the console-facing
//! bare-path per-file surfaces work against it:
//!
//! - `GET /v1/assets/static_site/{site}/{percent-encoded-path}` resolves a
//!   nested file of the published bundle — the #402 bare-path → prefixed-key
//!   remap on top of the #398 encoded-slash decode.
//! - `DELETE` on the same bare path unpublishes exactly that file; the site
//!   root (and the reserved `__site_manifest__`) keep serving.
//! - A legacy-shaped site (non-zip push, no serving channel) still round-trips
//!   its bare path unchanged — the #402 guard's passthrough case.

use crate::{
    cli::LocalArgs,
    constants::JSON_CONTENT,
    http::{free_addr, http_request_addr, HttpResponse},
};
use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::{
    env, fs,
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const ADMIN_AUTH: &str = "Authorization: Bearer site-e2e-admin-secret";
const CLIENT_AUTH: &str = "Authorization: Bearer site-e2e-client-secret";
/// Admin key scoped to a DIFFERENT tenant, for the #345 box-4 cross-tenant
/// binding refusal (the security half, which must hold at the API).
const OTHER_TENANT_AUTH: &str = "Authorization: Bearer site-e2e-other-secret";
const TENANT: &str = "org_site_e2e";
const SITE: &str = "docs-site";
const LEGACY_SITE: &str = "legacy-blob-site";
const NESTED_PATH: &str = "docs/deep/readme.md";
const NESTED_PATH_ENCODED: &str = "docs%2Fdeep%2Freadme.md";
const NESTED_CONTENT: &[u8] = b"# deep readme for the #402 remap";
const GATEWAY_READINESS_TIMEOUT: Duration = Duration::from_secs(180);

pub(crate) fn run_static_site_api(args: &LocalArgs) -> Result<()> {
    if !args.ferrogate_bin.exists() {
        bail!(
            "ferrogate binary does not exist at {}; run `cargo build -p ferrogate-cli` first or pass --ferrogate-bin",
            args.ferrogate_bin.display()
        );
    }

    let gateway_addr = free_addr()?;
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("static-site.yaml");
    fs::write(&config_path, scenario_config(&gateway_addr))?;
    let _gateway = GatewayGuard::start(&args.ferrogate_bin, &config_path, &gateway_addr)?;

    // Hosting is plan-gated (#168): create a plan with asset_hosting_enabled
    // and bind the tenant to it through the real Admin API.
    let plan = http_request_addr(
        &gateway_addr,
        "POST",
        "/admin/v1/plans",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"site-e2e-plan","name":"Site E2E plan","slug":"site-e2e-plan","asset_hosting_enabled":true}"#,
    )?;
    if plan.status != 200 && plan.status != 201 {
        bail!("failed to create hosting plan: {}", plan.raw);
    }
    let tenant = http_request_addr(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &[ADMIN_AUTH, JSON_CONTENT],
        &format!(
            r#"{{"id":"{TENANT}","name":"Site E2E","slug":"site-e2e","plan_id":"site-e2e-plan"}}"#
        ),
    )?;
    if tenant.status != 200 && tenant.status != 201 {
        bail!("failed to create hosting tenant: {}", tenant.raw);
    }

    // Publish a #397 zip bundle (stored entries; the unpacker does not
    // validate CRCs) with a nested path for the encoded-slash surfaces.
    let bundle = build_stored_zip(&[
        ("index.html", b"<h1>site e2e</h1>" as &[u8]),
        ("style.css", b"body{}"),
        (NESTED_PATH, NESTED_CONTENT),
    ]);
    let published = crate::http::http_request_addr_bytes(
        &gateway_addr,
        "PUT",
        &format!("/v1/assets/static_site/{SITE}/v1"),
        &[
            CLIENT_AUTH,
            "Content-Type: application/zip",
            // Explicit public opt-in (#397 serving policy): the site serves
            // anonymously, which is also what the serve assertions below rely on.
            "x-site-public: true",
        ],
        &bundle,
    )?;
    if published.status != 200 && published.status != 201 {
        bail!("bundle publish failed: {}", published.raw);
    }

    // The bundle serves: root resolves index.html, the nested path serves its
    // exact bytes.
    let root = http_request_addr(
        &gateway_addr,
        "GET",
        &format!("/sites/{TENANT}/{SITE}/"),
        &[],
        "",
    )?;
    if root.status != 200 || !root.body.contains("site e2e") {
        bail!("published site root did not serve index.html: {}", root.raw);
    }
    let nested_serve = http_request_addr(
        &gateway_addr,
        "GET",
        &format!("/sites/{TENANT}/{SITE}/{NESTED_PATH}"),
        &[],
        "",
    )?;
    if nested_serve.status != 200 || nested_serve.body.as_bytes() != NESTED_CONTENT {
        bail!(
            "nested path did not serve from the bundle: {}",
            nested_serve.raw
        );
    }

    // #402 + #398: the console-facing bare per-file download resolves the
    // #397 `__site_file__:{version}:{path}` key from the percent-encoded bare
    // path of the SERVING bundle.
    let bare_download = http_request_addr(
        &gateway_addr,
        "GET",
        &format!("/v1/assets/static_site/{SITE}/{NESTED_PATH_ENCODED}"),
        &[CLIENT_AUTH],
        "",
    )?;
    if bare_download.status != 200 || bare_download.body.as_bytes() != NESTED_CONTENT {
        bail!(
            "bare-path per-file download did not resolve the #397 bundle file: {}",
            bare_download.raw
        );
    }

    // Per-file unpublish on the same bare path removes exactly that file …
    let unpublish = http_request_addr(
        &gateway_addr,
        "DELETE",
        &format!("/v1/assets/static_site/{SITE}/{NESTED_PATH_ENCODED}"),
        &[CLIENT_AUTH],
        "",
    )?;
    if unpublish.status != 200 {
        bail!("bare-path per-file unpublish failed: {}", unpublish.raw);
    }
    let gone = http_request_addr(
        &gateway_addr,
        "GET",
        &format!("/v1/assets/static_site/{SITE}/{NESTED_PATH_ENCODED}"),
        &[CLIENT_AUTH],
        "",
    )?;
    if gone.status != 404 {
        bail!(
            "unpublished file still resolves (expected 404): {}",
            gone.raw
        );
    }
    // … while the site root (manifest + remaining files) keeps serving.
    let root_after = http_request_addr(
        &gateway_addr,
        "GET",
        &format!("/sites/{TENANT}/{SITE}/"),
        &[],
        "",
    )?;
    if root_after.status != 200 || !root_after.body.contains("site e2e") {
        bail!(
            "site root stopped serving after a per-file unpublish: {}",
            root_after.raw
        );
    }

    // Legacy control (#402 guard passthrough): a non-zip static_site push has
    // no serving channel; its bare path must round-trip byte-for-byte exactly
    // as before the remap existed.
    let legacy = push_asset(
        &gateway_addr,
        &format!("/v1/assets/static_site/{LEGACY_SITE}/v1"),
        "text/plain",
        b"legacy opaque blob",
    )?;
    if legacy.status != 200 && legacy.status != 201 {
        bail!("legacy-site push failed: {}", legacy.raw);
    }
    let legacy_pull = http_request_addr(
        &gateway_addr,
        "GET",
        &format!("/v1/assets/static_site/{LEGACY_SITE}/v1"),
        &[CLIENT_AUTH],
        "",
    )?;
    if legacy_pull.status != 200 || legacy_pull.body != "legacy opaque blob" {
        bail!(
            "legacy bare-path pull no longer round-trips: {}",
            legacy_pull.raw
        );
    }

    verify_console_agreement(&gateway_addr)?;
    verify_withheld_publish_agreement(args)?;
    verify_bind_terminals(args)?;

    println!("static-site-api scenario passed");
    Ok(())
}

/// #530 gate coverage: the bind terminal the HANDLER actually answers, for more
/// than one of its three arms.
///
/// #530 declared 200/201/202 on `bindSiteDomain` and sealed the status behind a
/// `BindTerminal` newtype whose constructor the handler cannot reach. Both are
/// real — forging `BindTerminal(StatusCode::NO_CONTENT)` in the handler is a
/// compile error (E0423), verified. But the acceptance box asked for the
/// gateway's *three-way return* to be pinned, and only the 202 arm was:
/// `every_bind_terminal_is_declared_in_the_openapi_document` pins the pure
/// selector against the spec, not the handler, and this scenario only ever bound
/// a fresh hostname.
///
/// The gap that leaves, verified by mutation before this box was written:
/// replacing the handler's `site_domain_bind_status(proven, existing.is_some())`
/// with `site_domain_bind_status(false, false)` — so every bind answers a
/// DECLARED-but-wrong 202 — passed `site_domains_test` (7/7), passed
/// `static-site-api`, and compiled clean, because the value it carries is
/// legitimately selected and nothing checked the other two arms end to end.
///
/// So this box drives the **200** arm: bind → prove ownership → re-bind. Proving
/// ownership offline is what makes it docker-free — `SiteDomainResolverBackend`
/// reads `FERROGATE_SITE_DOMAIN_RESOLVER` from the process environment, so a
/// `zone-file` backend pointed at a temp file is a real TXT oracle with no DNS.
///
/// The **201** arm (`proven && !existing`) is deliberately NOT asserted here: it
/// needs a proven verification with no binding row, and unbind deletes both
/// (`site_domains.rs:844` then `:863`), so no admin-API sequence found reaches
/// it. That is recorded as an open question on #530 rather than papered over
/// with a weaker assertion.
fn verify_bind_terminals(args: &LocalArgs) -> Result<()> {
    const SITE: &str = "bind-terminal-site";
    const HOSTNAME: &str = "proven.example.com";

    let gateway_addr = free_addr()?;
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("bind-terminals.yaml");
    fs::write(&config_path, scenario_config(&gateway_addr))?;

    // Readable and EMPTY, not absent: an unreadable zone file is an outage the
    // resolver reports as 503, which is a different branch than "the record is
    // not published yet". The 202 assertion below has to be the latter.
    let zone_path = dir.path().join("zone.txt");
    fs::write(&zone_path, "")?;
    let _gateway = GatewayGuard::start_with_env(
        &args.ferrogate_bin,
        &config_path,
        &gateway_addr,
        &[
            ("FERROGATE_SITE_DOMAIN_RESOLVER", "zone-file"),
            (
                "FERROGATE_SITE_DOMAIN_RESOLVER_ZONE_FILE",
                zone_path.to_str().context("zone file path is not UTF-8")?,
            ),
        ],
    )?;

    let plan = http_request_addr(
        &gateway_addr,
        "POST",
        "/admin/v1/plans",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"site-e2e-plan","name":"Site E2E plan","slug":"site-e2e-plan","asset_hosting_enabled":true}"#,
    )?;
    if plan.status != 200 && plan.status != 201 {
        bail!(
            "failed to create hosting plan (bind terminals): {}",
            plan.raw
        );
    }
    let tenant = http_request_addr(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &[ADMIN_AUTH, JSON_CONTENT],
        &format!(
            r#"{{"id":"{TENANT}","name":"Site E2E","slug":"site-e2e","plan_id":"site-e2e-plan"}}"#
        ),
    )?;
    if tenant.status != 200 && tenant.status != 201 {
        bail!(
            "failed to create hosting tenant (bind terminals): {}",
            tenant.raw
        );
    }
    let bundle = build_stored_zip(&[("index.html", b"<h1>bind terminals</h1>" as &[u8])]);
    let published = crate::http::http_request_addr_bytes(
        &gateway_addr,
        "PUT",
        &format!("/v1/assets/static_site/{SITE}/v1"),
        &[
            CLIENT_AUTH,
            "Content-Type: application/zip",
            "x-site-public: true",
        ],
        &bundle,
    )?;
    if published.status != 200 && published.status != 201 {
        bail!("bundle publish failed (bind terminals): {}", published.raw);
    }

    let bind_body =
        format!(r#"{{"hostname":"{HOSTNAME}","tenant_id":"{TENANT}","site":"{SITE}"}}"#);

    // --- 202: unproven. The record is simply not in the zone file yet. -------
    let pending = http_request_addr(
        &gateway_addr,
        "POST",
        "/admin/v1/site-domains",
        &[ADMIN_AUTH, JSON_CONTENT],
        &bind_body,
    )?;
    if pending.status != 202 {
        bail!(
            "an unproven bind must answer the 202 terminal: {}",
            pending.raw
        );
    }
    let pending_json: Value = serde_json::from_str(&pending.body)
        .with_context(|| format!("bind response is not JSON: {}", pending.raw))?;
    let verification = &pending_json["verification"];
    let record_name = verification["challenge_record_name"]
        .as_str()
        .with_context(|| {
            format!("bind response carried no challenge record name: {pending_json}")
        })?;
    let record_value = verification["challenge_record_value"]
        .as_str()
        .with_context(|| {
            format!("bind response carried no challenge record value: {pending_json}")
        })?;

    // --- publish the TXT the gateway asked for, and redeem it ---------------
    // The value comes from the response, never recomputed here: a harness that
    // derived it independently would keep passing if the gateway changed what
    // it asks operators to publish.
    fs::write(&zone_path, format!("{record_name} \"{record_value}\"\n"))?;
    let verified = http_request_addr(
        &gateway_addr,
        "POST",
        &format!("/admin/v1/site-domains/{HOSTNAME}/verify?tenant={TENANT}"),
        &[ADMIN_AUTH, JSON_CONTENT],
        "{}",
    )?;
    if verified.status != 200 {
        bail!(
            "redeeming a published challenge must succeed against the zone-file \
             resolver: {}",
            verified.raw
        );
    }
    if !verified.body.contains("\"serves\":true") && !verified.body.contains("\"serving\":true") {
        bail!(
            "verification reported success without marking the hostname as serving: {}",
            verified.raw
        );
    }

    // --- 200: proven AND already bound. The arm nothing exercised. ----------
    let rebound = http_request_addr(
        &gateway_addr,
        "POST",
        "/admin/v1/site-domains",
        &[ADMIN_AUTH, JSON_CONTENT],
        &bind_body,
    )?;
    if rebound.status != 200 {
        bail!(
            "re-binding an already-proven hostname must answer the 200 terminal, not \
             the 202 a fresh bind gets: {}",
            rebound.raw
        );
    }

    println!("static-site bind-terminal coverage passed");
    Ok(())
}

/// #345 gate coverage, the SECOND uncommitted-publish path: a bundle that is a
/// perfectly good ZIP but whose supply-chain screening did not clear.
///
/// `verify_console_agreement`'s box 3 drives the non-ZIP fallthrough. This is
/// the other one, and it is the half that keeps getting half-fixed, because it
/// is neither an error nor a bad upload: `assets.rs` takes the bundle-publish
/// path only when `screening.is_visible()` also holds, and #366 DELIBERATELY
/// stores a pending/quarantined bundle withheld rather than rejecting it. So a
/// clean-looking publish answers **200** with the SAME opaque-blob envelope, the
/// site is never served, and the console must not call it a publish.
///
/// Both facts the console's failure path depends on are OBSERVED here rather
/// than read off the source, which is exactly what `e28c452` / `f504810`
/// recorded as untested: that a withheld verdict produces the blob envelope at
/// all, and that `GET /v1/assets/withheld` -- the read
/// `explainUncommittedPublish` issues, with the same `asset_type`/`search`/
/// `limit` query and the same `total` comparison -- durably names the state by
/// the time the publish response is in the operator's hands.
///
/// A separate gateway process is needed because the screening posture comes from
/// the environment: `FERROGATE_ASSET_SCANNER_ASYNC_THRESHOLD_BYTES=1` defers
/// every non-trivial object to an async scan, which is exactly the `PendingScan`
/// (withheld, invisible) state. Canary: with that variable removed, the same PUT
/// answers `{"object":"static_site",…}` and this function fails on the envelope
/// assertion -- so it is testing the branch it claims to.
fn verify_withheld_publish_agreement(args: &LocalArgs) -> Result<()> {
    const SITE: &str = "withheld-site";
    const VERSION: &str = "1.0.0";

    let gateway_addr = free_addr()?;
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("static-site-withheld.yaml");
    fs::write(&config_path, scenario_config(&gateway_addr))?;
    let _gateway = GatewayGuard::start_with_env(
        &args.ferrogate_bin,
        &config_path,
        &gateway_addr,
        &[("FERROGATE_ASSET_SCANNER_ASYNC_THRESHOLD_BYTES", "1")],
    )?;

    let plan = http_request_addr(
        &gateway_addr,
        "POST",
        "/admin/v1/plans",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"site-e2e-plan","name":"Site E2E plan","slug":"site-e2e-plan","asset_hosting_enabled":true}"#,
    )?;
    if plan.status != 200 && plan.status != 201 {
        bail!("failed to create hosting plan (withheld): {}", plan.raw);
    }
    let tenant = http_request_addr(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &[ADMIN_AUTH, JSON_CONTENT],
        &format!(
            r#"{{"id":"{TENANT}","name":"Site E2E","slug":"site-e2e","plan_id":"site-e2e-plan"}}"#
        ),
    )?;
    if tenant.status != 200 && tenant.status != 201 {
        bail!("failed to create hosting tenant (withheld): {}", tenant.raw);
    }

    // A REAL zip bundle -- the console's client-side `PK\x03\x04` sniff would
    // pass it, and so does the gateway's `is_zip_archive`. Only the screening
    // verdict differs, which is the whole point: this fallthrough is NOT
    // predictable from the bytes the console can see.
    let bundle = build_stored_zip(&[("index.html", b"<h1>withheld</h1>" as &[u8])]);
    let published = crate::http::http_request_addr_bytes(
        &gateway_addr,
        "PUT",
        &format!("/v1/assets/static_site/{SITE}/{VERSION}"),
        &[
            CLIENT_AUTH,
            "Content-Type: application/zip",
            "x-site-public: true",
        ],
        &bundle,
    )?;
    if published.status != 200 && published.status != 201 {
        bail!(
            "a withheld bundle is stored, not rejected -- expected a 2xx: {}",
            published.raw
        );
    }
    let publish_body: Value = serde_json::from_str(&published.body)
        .with_context(|| format!("withheld publish response is not JSON: {}", published.raw))?;
    // THE POINT: a 2xx that is NOT a publish, in the very same shape the non-ZIP
    // fallthrough answers with. `isBundleCommit` (static-sites.tsx) is what
    // stands between this and a "Published …" toast for a site that does not
    // exist.
    if publish_body["object"] != "asset" {
        bail!(
            "a screening-withheld bundle must fall through to the opaque-blob \
             `asset` envelope, not the `static_site` publish envelope: {}",
            published.raw
        );
    }
    if publish_body["site"] != Value::Null
        || publish_body["file_count"] != Value::Null
        || publish_body["files"] != Value::Null
    {
        bail!(
            "the withheld fallthrough envelope must carry no publish fields: {}",
            published.raw
        );
    }

    // Nothing is served: the bundle was never unpacked into per-file objects or
    // a serving channel, so the site does not exist at its canonical URL.
    let serve = http_request_addr(
        &gateway_addr,
        "GET",
        &format!("/sites/{TENANT}/{SITE}/"),
        &[],
        "",
    )?;
    if serve.status == 200 {
        bail!(
            "a withheld bundle must never be served before it is proven clean: {}",
            serve.raw
        );
    }

    // And the reason is READABLE, at the exact URL + query the console issues
    // (`explainUncommittedPublish`): asset_type + search + a max page, so the
    // deduction is made from the whole answer rather than a first page.
    let withheld = http_request_addr(
        &gateway_addr,
        "GET",
        &format!("/v1/assets/withheld?asset_type=static_site&search={VERSION}&limit=1000"),
        &[CLIENT_AUTH],
        "",
    )?;
    if withheld.status != 200 {
        bail!("the withheld listing must be readable: {}", withheld.raw);
    }
    let withheld_body: Value = serde_json::from_str(&withheld.body)
        .with_context(|| format!("withheld listing is not JSON: {}", withheld.raw))?;
    let rows = withheld_body["data"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let row = rows
        .iter()
        .find(|row| row["name"] == SITE && row["version"] == VERSION)
        .with_context(|| {
            format!(
                "the withheld listing must name the bundle the publish did not commit, so the \
                 console can report WHY instead of guessing: {}",
                withheld.raw
            )
        })?;
    // `visibility` is what the console maps to "Pending scan" / "Quarantined".
    let visibility = row["visibility"].as_str().unwrap_or_default();
    if visibility != "pending_scan" && visibility != "quarantined" {
        bail!(
            "a withheld row must carry a withheld visibility, got {visibility:?}: {}",
            withheld.raw
        );
    }
    // Non-vacuity for the "absent from this listing therefore it was not a ZIP"
    // deduction: a bundle nobody withheld must NOT appear here.
    if rows.iter().any(|row| {
        row["name"] == "console-site" || row["name"] == SITE && row["version"] != VERSION
    }) {
        bail!(
            "a clean bundle must never appear in the withheld listing: {}",
            withheld.raw
        );
    }
    // And `total` is the pre-pagination count the console compares against the
    // rows it got, which is what makes that deduction honest rather than a guess.
    let total = withheld_body["total"].as_u64();
    if total != Some(rows.len() as u64) {
        bail!(
            "the withheld listing must report a `total` the console can compare against \
             the rows it received: {}",
            withheld.raw
        );
    }

    println!("static-site withheld-publish coverage passed");
    Ok(())
}

/// #345 gate coverage: prove the ADMIN CONSOLE's static-site surfaces agree with
/// what the gateway actually serves, over a real gateway process.
///
/// `114d925` / `550cb27` were corrections admitting the console had been
/// displaying, purging and binding against something other than the served
/// bundle, and both landed with "no live gateway ... read off sites.rs, not
/// observed". Everything below is the observation those commits could not make:
/// each console read is issued at the exact URL `static-sites.tsx` issues it,
/// and its answer is compared against the bytes/headers `/sites/{t}/{s}/`
/// returns.
fn verify_console_agreement(gateway_addr: &str) -> Result<()> {
    const SITE: &str = "console-site";
    let v1 = build_stored_zip(&[("index.html", b"<h1>V1</h1>" as &[u8]), ("app.css", b"a{}")]);
    let v2 = build_stored_zip(&[("index.html", b"<h1>V2</h1>" as &[u8]), ("app.css", b"b{}")]);

    // --- Box 1: publish, then open the canonical serve URL. ------------------
    let published = crate::http::http_request_addr_bytes(
        gateway_addr,
        "PUT",
        &format!("/v1/assets/static_site/{SITE}/1.0.0"),
        &[
            CLIENT_AUTH,
            "Content-Type: application/zip",
            "x-site-public: true",
            "x-site-spa-fallback: true",
            "x-site-cache-control: public, max-age=600",
        ],
        &v1,
    )?;
    if published.status != 200 && published.status != 201 {
        bail!("console-site publish failed: {}", published.raw);
    }
    // The publish answered with the BUNDLE envelope, not the opaque-blob one.
    let publish_body: Value = serde_json::from_str(&published.body)
        .with_context(|| format!("publish response is not JSON: {}", published.raw))?;
    if publish_body["object"] != "static_site" {
        bail!(
            "a committed bundle must answer with the static_site envelope: {}",
            published.raw
        );
    }
    let serve = http_request_addr(
        gateway_addr,
        "GET",
        &format!("/sites/{TENANT}/{SITE}/"),
        &[],
        "",
    )?;
    if serve.status != 200 || serve.body != "<h1>V1</h1>" {
        bail!(
            "canonical serve URL did not return the published bytes: {}",
            serve.raw
        );
    }

    // --- Box 2: every displayed field matches the SERVED bundle. -------------
    let (serving_version, manifest) = console_active_bundle(gateway_addr, SITE)?;
    if serving_version.as_deref() != Some("1.0.0") {
        bail!("serving channel should resolve 1.0.0, got {serving_version:?}");
    }
    assert_console_matches_serve(gateway_addr, SITE, &manifest, &serve, "1.0.0")?;

    // --- The 114d925 core: after a ROLLBACK the console must follow the
    // channel, not the mutable marker. ---------------------------------------
    let republished = crate::http::http_request_addr_bytes(
        gateway_addr,
        "PUT",
        &format!("/v1/assets/static_site/{SITE}/2.0.0"),
        &[
            CLIENT_AUTH,
            "Content-Type: application/zip",
            "x-site-public: true",
            "x-site-cache-control: no-store",
        ],
        &v2,
    )?;
    if republished.status != 200 && republished.status != 201 {
        bail!("console-site republish failed: {}", republished.raw);
    }
    let rollback = http_request_addr(
        gateway_addr,
        "PUT",
        &format!("/v1/assets/static_site/{SITE}/channels/serving?version=1.0.0"),
        &[CLIENT_AUTH],
        "",
    )?;
    if rollback.status != 200 {
        bail!("serving-channel rollback failed: {}", rollback.raw);
    }

    let served_after = http_request_addr(
        gateway_addr,
        "GET",
        &format!("/sites/{TENANT}/{SITE}/"),
        &[],
        "",
    )?;
    if served_after.body != "<h1>V1</h1>" {
        bail!(
            "a channel rollback must re-point what /sites serves: {}",
            served_after.raw
        );
    }
    let (rolled_version, rolled_manifest) = console_active_bundle(gateway_addr, SITE)?;
    if rolled_version.as_deref() != Some("1.0.0") {
        bail!("post-rollback serving channel should be 1.0.0, got {rolled_version:?}");
    }
    assert_console_matches_serve(gateway_addr, SITE, &rolled_manifest, &served_after, "1.0.0")?;

    // …and pin WHY that resolution is load-bearing: the mutable marker (what the
    // console read before 114d925) still describes the last-PUBLISHED bundle, so
    // reading it would contradict the gateway on every policy field. If this
    // ever stops diverging the regression guard above has gone vacuous.
    let marker = http_request_addr(
        gateway_addr,
        "GET",
        &format!("/v1/assets/static_site/{SITE}/__site_manifest__"),
        &[CLIENT_AUTH],
        "",
    )?;
    let marker_json: Value = serde_json::from_str(&marker.body)
        .with_context(|| format!("marker is not JSON: {}", marker.raw))?;
    if marker_json["bundle_version"] != "2.0.0" || marker_json["cache_control"] != "no-store" {
        bail!(
            "expected the marker to still describe the last-published bundle (the \
             pre-114d925 lie this guard exists to catch): {}",
            marker.raw
        );
    }

    // --- Box 3: a republish the gateway does NOT commit as a bundle. ---------
    // The console's own `looksLikeZip` gate is name/MIME only, so a corrupt file
    // named `site.zip` reaches the gateway; `assets.rs` only takes the bundle
    // path for a real ZIP that screens clean, and otherwise stores an opaque
    // blob. The previously committed site must keep serving.
    let corrupt = crate::http::http_request_addr_bytes(
        gateway_addr,
        "PUT",
        &format!("/v1/assets/static_site/{SITE}/3.0.0"),
        &[
            CLIENT_AUTH,
            "Content-Type: application/zip",
            "x-site-public: true",
        ],
        b"not a zip at all, just bytes that came from a truncated upload",
    )?;
    let corrupt_body: Value = serde_json::from_str(&corrupt.body)
        .with_context(|| format!("corrupt-publish response is not JSON: {}", corrupt.raw))?;
    // Pin the ACTUAL outcome: a 2xx carrying the OPAQUE-BLOB envelope. Nothing
    // was published, so a console that reports this as a successful publish is
    // claiming a deployment the gateway never made (#345 box 3).
    if !(corrupt.status == 200 || corrupt.status == 201) || corrupt_body["object"] != "asset" {
        bail!(
            "expected a non-zip static_site push to fall through to the opaque blob \
             store with a 2xx `asset` envelope: {}",
            corrupt.raw
        );
    }
    if corrupt_body["site"] != Value::Null || corrupt_body["file_count"] != Value::Null {
        bail!(
            "the fallthrough envelope must NOT carry publish fields: {}",
            corrupt.raw
        );
    }
    let after_failure = http_request_addr(
        gateway_addr,
        "GET",
        &format!("/sites/{TENANT}/{SITE}/"),
        &[],
        "",
    )?;
    if after_failure.status != 200 || after_failure.body != "<h1>V1</h1>" {
        bail!(
            "an uncommitted republish must leave the previous bundle serving: {}",
            after_failure.raw
        );
    }
    let (after_version, _) = console_active_bundle(gateway_addr, SITE)?;
    if after_version.as_deref() != Some("1.0.0") {
        bail!("an uncommitted republish must not move the serving channel: {after_version:?}");
    }

    // --- Box 4: domain binding is refused SERVER-SIDE. ----------------------
    // Cross-tenant: a tenant-scoped admin key aimed at another tenant's site.
    let cross_tenant = http_request_addr(
        gateway_addr,
        "POST",
        "/admin/v1/site-domains",
        &[OTHER_TENANT_AUTH, JSON_CONTENT],
        &format!(r#"{{"hostname":"stolen.example.com","tenant_id":"{TENANT}","site":"{SITE}"}}"#),
    )?;
    if cross_tenant.status != 403 || !cross_tenant.body.contains("tenant_scope_denied") {
        bail!(
            "a cross-tenant site-domain bind must be refused by the API, not just the \
             picker: {}",
            cross_tenant.raw
        );
    }
    // Nonexistent site, caller's own tenant.
    let ghost = http_request_addr(
        gateway_addr,
        "POST",
        "/admin/v1/site-domains",
        &[ADMIN_AUTH, JSON_CONTENT],
        &format!(r#"{{"hostname":"ghost.example.com","tenant_id":"{TENANT}","site":"no-such"}}"#),
    )?;
    if ghost.status != 404 || !ghost.body.contains("site_not_found") {
        bail!(
            "binding a nonexistent site must 404 site_not_found: {}",
            ghost.raw
        );
    }

    // --- Box 5: bound-domain liveness is the gateway's, not an optimistic
    // label, and unbind is confirmed. ----------------------------------------
    let bind = http_request_addr(
        gateway_addr,
        "POST",
        "/admin/v1/site-domains",
        &[ADMIN_AUTH, JSON_CONTENT],
        &format!(r#"{{"hostname":"live.example.com","tenant_id":"{TENANT}","site":"{SITE}"}}"#),
    )?;
    if bind.status != 202 {
        bail!(
            "a fresh bind should be accepted-but-pending (202): {}",
            bind.raw
        );
    }
    let detail = http_request_addr(
        gateway_addr,
        "GET",
        "/admin/v1/site-domains/live.example.com",
        &[ADMIN_AUTH],
        "",
    )?;
    let detail_json: Value = serde_json::from_str(&detail.body)
        .with_context(|| format!("site-domain detail is not JSON: {}", detail.raw))?;
    let domain = &detail_json["site_domain"];
    // The two fields 550cb27 wired into the console must both be present, and a
    // freshly bound hostname must report itself NOT live (#488) -- the exact
    // "server-reported unhealthy state shown as implicitly healthy" that commit
    // set out to fix.
    if domain["serving"] != Value::Bool(false) {
        bail!(
            "a freshly bound hostname must report serving=false, not an optimistic \
             label: {}",
            detail.raw
        );
    }
    if domain["verification_state"] != "pending_verification" {
        bail!(
            "the detail read must carry the verification state the console renders: {}",
            detail.raw
        );
    }
    if !detail
        .body
        .contains("_ferrogate-challenge.live.example.com")
    {
        bail!(
            "a pending binding must tell the operator which TXT record to publish: {}",
            detail.raw
        );
    }
    let unbind = http_request_addr(
        gateway_addr,
        "DELETE",
        "/admin/v1/site-domains/live.example.com",
        &[ADMIN_AUTH],
        "",
    )?;
    if unbind.status != 200 || !unbind.body.contains("\"deleted\":true") {
        bail!("unbind was not confirmed: {}", unbind.raw);
    }
    let gone = http_request_addr(
        gateway_addr,
        "GET",
        "/admin/v1/site-domains/live.example.com",
        &[ADMIN_AUTH],
        "",
    )?;
    if gone.status != 404 {
        bail!("an unbound hostname must stop resolving: {}", gone.raw);
    }

    println!("static-site console-agreement coverage passed");
    Ok(())
}

/// Issues the two reads `static-sites.tsx`'s `fetchActiveSiteBundle` issues, in
/// the same order and at the same URLs: the asset REGISTRY manifest, then the
/// manifest row of whatever version the `serving` channel points at.
fn console_active_bundle(gateway_addr: &str, site: &str) -> Result<(Option<String>, Value)> {
    let registry = http_request_addr(
        gateway_addr,
        "GET",
        &format!("/v1/assets/static_site/{site}/manifest"),
        &[CLIENT_AUTH],
        "",
    )?;
    if registry.status != 200 {
        bail!("console registry read failed: {}", registry.raw);
    }
    let registry_json: Value = serde_json::from_str(&registry.body)
        .with_context(|| format!("registry manifest is not JSON: {}", registry.raw))?;
    let serving_version = registry_json["channels"]
        .as_array()
        .and_then(|channels| {
            channels
                .iter()
                .find(|channel| channel["channel"] == "serving")
        })
        .and_then(|channel| channel["version"].as_str())
        .map(str::to_string);
    let reference = serving_version
        .clone()
        .unwrap_or_else(|| "__site_manifest__".to_string());
    let manifest = http_request_addr(
        gateway_addr,
        "GET",
        &format!("/v1/assets/static_site/{site}/{reference}"),
        &[CLIENT_AUTH],
        "",
    )?;
    if manifest.status != 200 {
        bail!(
            "console bundle-manifest read at the serving version failed -- the read the \
             whole page is built on: {}",
            manifest.raw
        );
    }
    let manifest_json: Value = serde_json::from_str(&manifest.body)
        .with_context(|| format!("bundle manifest is not JSON: {}", manifest.raw))?;
    Ok((serving_version, manifest_json))
}

/// Compares each field the console DISPLAYS against what the serve path returned
/// for the same site: the em-dash between "renders a value" and "renders the
/// truth" is the whole point of #345 box 2.
fn assert_console_matches_serve(
    gateway_addr: &str,
    site: &str,
    manifest: &Value,
    serve: &HttpResponse,
    expected_version: &str,
) -> Result<()> {
    if manifest["bundle_version"] != expected_version {
        bail!(
            "displayed version {} != served bundle {expected_version}",
            manifest["bundle_version"]
        );
    }
    // Cache policy: the displayed string must be the header the site actually
    // answers with.
    let displayed_cache = manifest["cache_control"]
        .as_str()
        .context("manifest carries no cache_control to display")?;
    let served_cache = serve
        .raw
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("cache-control")
                .then(|| value.trim().to_string())
        })
        .context("serve response carried no Cache-Control header")?;
    if displayed_cache != served_cache {
        bail!("displayed cache policy {displayed_cache:?} != served {served_cache:?}");
    }
    // Public: the displayed flag must match anonymous servability, which the
    // `serve` response (issued with NO credentials) already proves.
    if manifest["public"] != Value::Bool(true) || serve.status != 200 {
        bail!(
            "displayed public flag {} disagrees with anonymous serve status {}",
            manifest["public"],
            serve.status
        );
    }
    // Files/bytes/hashes: each displayed entry must be the object the gateway
    // serves, byte for byte.
    let files = manifest["files"]
        .as_array()
        .context("manifest carries no file list to display")?;
    let mut total = 0u64;
    for file in files {
        let path = file["path"].as_str().context("file entry without a path")?;
        let size = file["size_bytes"]
            .as_u64()
            .context("file entry without a size")?;
        total += size;
        let fetched = http_request_addr(
            gateway_addr,
            "GET",
            &format!("/sites/{TENANT}/{site}/{path}"),
            &[],
            "",
        )?;
        if fetched.status != 200 {
            bail!("displayed file {path} does not serve: {}", fetched.raw);
        }
        if fetched.body.len() as u64 != size {
            bail!(
                "displayed size {size} for {path} != {} bytes actually served",
                fetched.body.len()
            );
        }
        // The manifest hash the drawer prints must be the served object's ETag.
        let hash = file["content_hash"].as_str().unwrap_or_default();
        if !fetched.raw.contains(hash) {
            bail!(
                "displayed hash {hash} for {path} is not the ETag the gateway serves: {}",
                fetched.raw
            );
        }
    }
    if total == 0 {
        bail!("displayed byte total must be non-zero for a published bundle");
    }
    // SPA fallback: the displayed flag must match what an unmatched deep path
    // actually does.
    let spa = manifest["spa_fallback"] == Value::Bool(true);
    let deep = http_request_addr(
        gateway_addr,
        "GET",
        &format!("/sites/{TENANT}/{site}/client/route/does-not-exist"),
        &[],
        "",
    )?;
    let fell_back = deep.status == 200 && deep.body.contains("<h1>");
    if spa != fell_back {
        bail!(
            "displayed spa_fallback={spa} but an unmatched path returned {} ({})",
            deep.status,
            deep.body
        );
    }
    // Publish timestamp: must be present and sane, not a render-time clock.
    let created = manifest["created_at_unix"].as_i64().unwrap_or_default();
    if created <= 0 {
        bail!("displayed publish timestamp is absent or zero: {manifest}");
    }
    Ok(())
}

fn push_asset(addr: &str, path: &str, content_type: &str, body: &[u8]) -> Result<HttpResponse> {
    let content_type_header = format!("Content-Type: {content_type}");
    crate::http::http_request_addr_bytes(
        addr,
        "PUT",
        path,
        &[CLIENT_AUTH, &content_type_header],
        body,
    )
}

/// Minimal stored-method zip (no compression; the gateway's unpacker does not
/// validate CRCs) — the same construction the sites unit tests use.
fn build_stored_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();

    for (name, data) in entries {
        let offset = out.len() as u32;
        let name_bytes = name.as_bytes();
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // method: stored
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(data);

        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // method: stored
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name_bytes);
    }

    let cd_offset = out.len() as u32;
    let cd_size = central.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn scenario_config(gateway_addr: &str) -> String {
    format!(
        r#"listen: {gateway_addr:?}
cluster:
  enabled: true
  cluster_id: "static-site-e2e"
  node_id: "static-site-node"
  node_region: "local"
  node_zone: "local-a"
  state_backend: "local"
  counter_backend: "local"
providers:
  - name: "openai"
    kind: "openai"
    base_url: "http://127.0.0.1:1/v1"
    api_key_env: "FERROGATE_PROVIDER_SECRET"
models:
  - name: "fast-chat"
    provider: "openai"
    provider_model: "gpt-4o-mini"
    capabilities: ["chat"]
api_keys:
  - id: "site-e2e-admin"
    name: "Static site E2E host operator"
    key: "site-e2e-admin-secret"
    scopes: ["admin.read", "admin.write"]
  - id: "site-e2e-client"
    name: "Static site E2E tenant client"
    key: "site-e2e-client-secret"
    scopes: ["assets.read", "assets.write"]
    organization_id: "org_site_e2e"
    project_id: "project_site_e2e"
  - id: "site-e2e-other-tenant"
    name: "Static site E2E foreign tenant admin"
    key: "site-e2e-other-secret"
    scopes: ["admin.read", "admin.write", "assets.read", "assets.write"]
    organization_id: "org_site_e2e_other"
    project_id: "project_site_e2e_other"
"#
    )
}

struct GatewayGuard {
    child: Child,
}

impl GatewayGuard {
    fn start(binary: &Path, config_path: &Path, gateway_addr: &str) -> Result<Self> {
        Self::start_with_env(binary, config_path, gateway_addr, &[])
    }

    /// Same, plus extra process environment. The supply-chain screening posture
    /// (#366) is read from the gateway's ENVIRONMENT rather than its YAML, so
    /// the withheld-publish coverage needs its own gateway with a different one.
    fn start_with_env(
        binary: &Path,
        config_path: &Path,
        gateway_addr: &str,
        extra_env: &[(&str, &str)],
    ) -> Result<Self> {
        let mut command = Command::new(binary);
        command
            .args(["run", "--config"])
            .arg(config_path)
            .env("FERROGATE_PROVIDER_SECRET", "provider-secret");
        for (key, value) in extra_env {
            command.env(key, value);
        }
        let child = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(
                if env::var("FERROGATE_TEST_DEBUG_STDERR").is_ok_and(|value| value == "1") {
                    Stdio::inherit()
                } else {
                    Stdio::null()
                },
            )
            .spawn()
            .with_context(|| format!("failed to start {}", binary.display()))?;
        let mut guard = Self { child };
        guard.wait_for_readiness(gateway_addr)?;
        Ok(guard)
    }

    fn wait_for_readiness(&mut self, gateway_addr: &str) -> Result<()> {
        let started = Instant::now();
        let mut last = String::new();
        while started.elapsed() < GATEWAY_READINESS_TIMEOUT {
            if let Some(status) = self.child.try_wait()? {
                bail!("FerroGate exited before static-site E2E readiness: {status}");
            }
            match http_request_addr(gateway_addr, "GET", "/healthz", &[], "") {
                Ok(response) if response.status == 200 => return Ok(()),
                Ok(response) => last = response.raw,
                Err(error) => last = error.to_string(),
            }
            thread::sleep(Duration::from_millis(100));
        }
        bail!("timed out waiting for the static-site E2E gateway: {last}")
    }
}

impl Drop for GatewayGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// Silence an unused-import lint if Value ends up unneeded during evolution.
#[allow(unused)]
fn _assert_json(_: &Value) {}
