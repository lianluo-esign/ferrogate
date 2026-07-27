// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for the generic resource command wiring: the clap tree the
//! registry drives is internally valid, the resource args fold into the right
//! request input, and the generic table renderer projects the three response
//! shapes.

use super::*;
use ferrogate_cli_core::register_resource_families;
use serde_json::json;

fn registry() -> Registry {
    let mut registry = Registry::new();
    register_resource_families(&mut registry).expect("families register");
    registry
}

/// The generated `ctl` subtree is a valid clap command tree (the builder-side
/// analogue of the derive `debug_assert`). Exercises every registered group and
/// verb plus the shared global + resource args on each leaf.
#[test]
fn generated_ctl_tree_is_valid() {
    build_ctl_command(&registry()).debug_assert();
}

/// The `ctl` tree offers one subcommand per registered group, each with one
/// subcommand per declared verb — proving the tree is metadata-driven, not
/// hand-enumerated.
#[test]
fn ctl_tree_mirrors_the_registry() {
    let registry = registry();
    let ctl = build_ctl_command(&registry);
    for group in registry.groups() {
        let group_cmd = ctl
            .get_subcommands()
            .find(|command| command.get_name() == group.name)
            .unwrap_or_else(|| panic!("group '{}' missing from ctl tree", group.name));
        for verb in &group.verbs {
            assert!(
                group_cmd
                    .get_subcommands()
                    .any(|command| command.get_name() == verb.name),
                "verb '{} {}' missing from ctl tree",
                group.name,
                verb.name
            );
        }
    }
}

/// A representative invocation parses through the generated tree into the group
/// / verb / args a dispatch would consume.
#[test]
fn parses_a_get_with_output_flag() {
    let registry = registry();
    let command = build_ctl_command(&registry);
    let matches = command
        .try_get_matches_from(["ctl", "virtual-keys", "get", "vk-1", "--output", "json"])
        .expect("valid invocation parses");
    let (group, group_matches) = matches.subcommand().unwrap();
    assert_eq!(group, "virtual-keys");
    let (verb, verb_matches) = group_matches.subcommand().unwrap();
    assert_eq!(verb, "get");

    let resource = ResourceArgs::from_arg_matches(verb_matches).unwrap();
    assert_eq!(resource.segments, vec!["vk-1".to_string()]);
    let global = GlobalArgs::from_arg_matches(verb_matches).unwrap();
    assert_eq!(global.output.as_deref(), Some("json"));
}

#[test]
fn resource_args_fold_segments_body_and_list() {
    let registry = registry();
    let command = build_ctl_command(&registry);
    let matches = command
        .try_get_matches_from([
            "ctl",
            "quota-policies",
            "update",
            "tenant",
            "acme",
            "--data",
            r#"{"limit":5}"#,
            "--limit",
            "20",
            "--offset",
            "40",
            "--filter",
            "status=active",
        ])
        .expect("valid invocation parses");
    let verb_matches = matches
        .subcommand()
        .unwrap()
        .1
        .subcommand()
        .unwrap()
        .1
        .clone();
    let resource = ResourceArgs::from_arg_matches(&verb_matches).unwrap();
    let input = resource.to_input().unwrap();
    assert_eq!(
        input.segments,
        vec!["tenant".to_string(), "acme".to_string()]
    );
    assert_eq!(input.body, Some(json!({"limit": 5})));
    // The list params fold pagination + the server-side filter.
    let spec = build_request("quota-policies", "update", &input).unwrap();
    assert_eq!(spec.method.as_str(), "PATCH");
    assert_eq!(spec.path, "/admin/v1/quota-policies/tenant/acme");
    assert_eq!(spec.body, Some(json!({"limit": 5})));
}

#[test]
fn malformed_filter_is_a_usage_error() {
    let args = ResourceArgs {
        segments: vec![],
        data: None,
        file: None,
        limit: None,
        offset: None,
        filters: vec!["missing-equals".to_string()],
        sorts: vec![],
        all_pages: false,
        dry_run: false,
    };
    let error = args.to_input().unwrap_err();
    assert!(error.to_string().contains("KEY=VALUE"));
}

#[test]
fn malformed_body_is_a_usage_error() {
    let args = ResourceArgs {
        segments: vec![],
        data: Some("not json".to_string()),
        file: None,
        limit: None,
        offset: None,
        filters: vec![],
        sorts: vec![],
        all_pages: false,
        dry_run: false,
    };
    let error = args.to_input().unwrap_err();
    assert!(error.to_string().contains("not valid JSON"));
}

#[test]
fn render_table_projects_an_array_of_objects() {
    let body = json!([
        {"id": "a", "name": "Alpha"},
        {"id": "b", "name": "Beta", "extra": 1},
    ]);
    let table = render_table(&body).unwrap();
    assert!(table.contains("ID") && table.contains("NAME") && table.contains("EXTRA"));
    assert!(table.contains("Alpha") && table.contains("Beta"));
    // A row missing a union column renders a placeholder, never a ragged table.
    assert!(table.contains('-'));
}

#[test]
fn render_table_unwraps_a_list_envelope() {
    let body = json!({"object": "list", "data": [{"id": "x"}], "total": 1});
    let table = render_table(&body).unwrap();
    assert!(table.contains("ID"));
    assert!(table.contains('x'));
}

#[test]
fn render_table_projects_a_single_object() {
    let body = json!({"service": "ferrogate", "runtime": "pingora"});
    let table = render_table(&body).unwrap();
    assert!(table.contains("FIELD") && table.contains("VALUE"));
    assert!(table.contains("service") && table.contains("ferrogate"));
}

#[test]
fn render_table_handles_empty_and_scalar() {
    assert_eq!(render_table(&json!([])).unwrap(), "(no results)");
    assert_eq!(render_table(&Value::Null).unwrap(), "(empty)");
    assert_eq!(render_table(&json!("hello")).unwrap(), "hello");
}

/// `--sort` is a real flag on every generic verb and folds into the request as
/// repeatable server-side `sort` query parameters.
#[test]
fn sort_flags_reach_the_request_query() {
    let registry = registry();
    let command = build_ctl_command(&registry);
    let matches = command
        .try_get_matches_from([
            "ctl",
            "virtual-keys",
            "list",
            "--sort",
            "tier",
            "--sort",
            "-created_at",
        ])
        .expect("valid invocation parses");
    let verb_matches = matches
        .subcommand()
        .unwrap()
        .1
        .subcommand()
        .unwrap()
        .1
        .clone();
    let input = ResourceArgs::from_arg_matches(&verb_matches)
        .unwrap()
        .to_input()
        .unwrap();
    let spec = build_request("virtual-keys", "list", &input).unwrap();
    assert!(
        spec.query
            .contains(&("sort".to_string(), "tier".to_string())),
        "query: {:?}",
        spec.query
    );
    assert!(
        spec.query
            .contains(&("sort".to_string(), "-created_at".to_string())),
        "query: {:?}",
        spec.query
    );
}

#[test]
fn empty_sort_key_is_a_usage_error() {
    let args = ResourceArgs {
        segments: vec![],
        data: None,
        file: None,
        limit: None,
        offset: None,
        filters: vec![],
        sorts: vec!["   ".to_string()],
        all_pages: false,
        dry_run: false,
    };
    let error = args.to_input().unwrap_err();
    assert!(error.to_string().contains("--sort"));
}

/// `--sort --output json` must not silently sort by "--output".
///
/// `allow_hyphen_values` is required so the documented descending form
/// `--sort -created_at` parses, but it also makes clap hand the *next flag* to
/// `--sort`: `--output` becomes the sort key and `json` a stray positional
/// segment, so the command targets the wrong resource path with a nonsense sort
/// and no complaint. A field name never begins with `--`, so this is a
/// forgotten value.
#[test]
fn a_flag_swallowed_as_a_sort_key_is_a_usage_error() {
    let registry = registry();
    let command = build_ctl_command(&registry);
    let matches = command
        .try_get_matches_from(["ctl", "virtual-keys", "list", "--sort", "--output", "json"])
        .expect("allow_hyphen_values means clap itself accepts this");
    let verb_matches = matches
        .subcommand()
        .unwrap()
        .1
        .subcommand()
        .unwrap()
        .1
        .clone();
    let args = ResourceArgs::from_arg_matches(&verb_matches).unwrap();
    assert_eq!(
        args.sorts,
        vec!["--output".to_string()],
        "this test is only meaningful while clap still swallows the flag"
    );
    let error = args.to_input().unwrap_err();
    assert!(
        error.to_string().contains("--output"),
        "the message must name the flag that was swallowed: {error}"
    );
}

/// `--all-pages` is a real flag, and it hands the cursor to the walker: the
/// spec it builds carries no baked-in `offset`/`limit`, because `--limit` is
/// the walk's page size rather than a one-page window.
#[test]
fn all_pages_leaves_the_cursor_to_the_walker() {
    let registry = registry();
    let command = build_ctl_command(&registry);
    let matches = command
        .try_get_matches_from([
            "ctl",
            "virtual-keys",
            "list",
            "--all-pages",
            "--limit",
            "25",
        ])
        .expect("valid invocation parses");
    let verb_matches = matches
        .subcommand()
        .unwrap()
        .1
        .subcommand()
        .unwrap()
        .1
        .clone();
    let args = ResourceArgs::from_arg_matches(&verb_matches).unwrap();
    assert!(args.all_pages);
    assert_eq!(args.limit, Some(25));
    let spec = build_request("virtual-keys", "list", &args.to_input().unwrap()).unwrap();
    assert!(
        !spec
            .query
            .iter()
            .any(|(key, _)| key == "offset" || key == "limit"),
        "the walker owns the cursor, spec query: {:?}",
        spec.query
    );
}

/// `--all-pages` and `--offset` are contradictory (every page vs. one page), so
/// clap rejects the combination instead of silently honoring one.
#[test]
fn all_pages_conflicts_with_offset() {
    let registry = registry();
    let command = build_ctl_command(&registry);
    assert!(command
        .try_get_matches_from([
            "ctl",
            "virtual-keys",
            "list",
            "--all-pages",
            "--offset",
            "10"
        ])
        .is_err());
}

#[test]
fn truncation_notice_flags_a_partial_page_against_a_known_total() {
    let body = json!({"object": "list", "data": [{"id": "a"}, {"id": "b"}], "total": 9});
    let notice = truncation_notice(&body, 0, Some(2)).expect("a partial page must be announced");
    assert!(notice.contains("showing 2 of 9"), "{notice}");
    assert!(notice.contains("--all-pages"), "{notice}");
}

#[test]
fn truncation_notice_is_silent_when_the_page_is_the_whole_collection() {
    let body = json!({"object": "list", "data": [{"id": "a"}, {"id": "b"}], "total": 2});
    assert_eq!(truncation_notice(&body, 0, Some(50)), None);
    // A later page that reaches the total is complete too.
    let tail = json!({"object": "list", "data": [{"id": "c"}], "total": 3});
    assert_eq!(truncation_notice(&tail, 2, Some(2)), None);
}

/// Without a server total, an exactly-full page is indistinguishable from a
/// truncated one — the operator is told that rather than left to assume.
#[test]
fn truncation_notice_warns_on_a_full_page_with_no_total() {
    let body = json!([{"id": "a"}, {"id": "b"}]);
    let notice = truncation_notice(&body, 0, Some(2)).expect("a full page must be announced");
    assert!(notice.contains("more rows may exist"), "{notice}");
    // A short page under the same conditions is provably the last page.
    assert_eq!(truncation_notice(&json!([{"id": "a"}]), 0, Some(2)), None);
}

/// The default `list` — no `--limit` at all — against an endpoint that applies
/// a server-side page size and reports no total must still warn.
///
/// This is the most likely invocation in practice and was the one silent case
/// left: the notice consulted only the operator's `--limit`, so with none
/// passed the no-total arm returned `None` and a truncated page looked
/// complete. The envelope's own `limit` — carried by every paginated list
/// schema in the contract — is what closes it.
#[test]
fn truncation_notice_uses_the_envelope_page_size_when_no_limit_was_passed() {
    let body = json!({"object": "list", "data": [{"id": "a"}, {"id": "b"}], "limit": 2});
    let notice =
        truncation_notice(&body, 0, None).expect("a server-capped full page must be announced");
    assert!(notice.contains("more rows may exist"), "{notice}");
    // A page under the server's own limit is provably the last page.
    assert_eq!(
        truncation_notice(
            &json!({"object": "list", "data": [{"id": "a"}], "limit": 2}),
            0,
            None
        ),
        None
    );
}

/// The payment-attempt page verbatim from the admin contract (#352): a full
/// page, a server-applied `limit`, no `total`, and a cursor to resume from.
fn cursor_page() -> Value {
    json!({
        "object": "list",
        "data": [{"id": "att-2"}, {"id": "att-1"}],
        "limit": 2,
        "next_cursor": "1753500000:att-1",
    })
}

/// `--offset` against a cursor endpoint is refused, not answered with page one.
///
/// `ctl payment-attempts list --offset 50` used to print the FIRST page and exit
/// 0: the handler parses `tenant_id`, `limit` and `cursor` and never looks at
/// `offset`. On a money-audit surface that is an operator reading rows 1-50
/// believing they are rows 51-100. Delete the `cursor_offset_refusal` call in
/// `execute` and nothing else in the suite notices.
#[test]
fn an_offset_a_cursor_endpoint_ignores_is_refused_rather_than_answered() {
    let refusal = cursor_offset_refusal(&cursor_page(), Some(50), "/admin/v1/payment-attempts")
        .expect("an ignored offset must be refused");
    assert!(refusal.contains("cursor-paginated"), "{refusal}");
    assert!(refusal.contains("page ONE"), "{refusal}");
    // The refusal is actionable: it quotes the continuation the server gave.
    assert!(
        refusal.contains("next_cursor=1753500000:att-1"),
        "{refusal}"
    );

    // Not a refusal when there is nothing to be wrong about.
    assert_eq!(
        cursor_offset_refusal(&cursor_page(), None, "/admin/v1/payment-attempts"),
        None,
        "no --offset, no misreading"
    );
    assert_eq!(
        cursor_offset_refusal(&cursor_page(), Some(0), "/admin/v1/payment-attempts"),
        None,
        "offset 0 is page one, which is what a cursor endpoint returns anyway"
    );
    // An OFFSET-paginated endpoint honors the offset: refusing it would break
    // every list verb in the contract that actually paginates by window.
    let offset_page =
        json!({"object": "list", "data": [{"id": "a"}], "total": 9, "offset": 50, "limit": 1});
    assert_eq!(
        cursor_offset_refusal(&offset_page, Some(50), "/admin/v1/virtual-keys"),
        None
    );
    // A non-list document has no pages to be wrong about.
    assert_eq!(
        cursor_offset_refusal(
            &json!({"id": "att-1"}),
            Some(50),
            "/admin/v1/payment-attempts"
        ),
        None
    );
}

/// A cursor page's completeness comes from its own cursor, not from window
/// arithmetic — and the notice must not point at `--all-pages`, which now
/// refuses cursor endpoints.
///
/// Both directions are load-bearing: a FULL page with a null `next_cursor` is
/// the whole answer and must stay silent (the window rule would have warned),
/// and a SHORT page with a live cursor has more rows and must warn (the window
/// rule would have been silent — it reads a short page as the last page).
#[test]
fn truncation_notice_reads_the_cursor_on_a_cursor_page() {
    let notice = truncation_notice(&cursor_page(), 0, Some(2)).expect("more rows exist");
    assert!(notice.contains("pages by cursor"), "{notice}");
    assert!(notice.contains("next_cursor=1753500000:att-1"), "{notice}");
    assert!(
        !notice.contains("re-run with --all-pages to"),
        "advice that cannot work: --all-pages refuses cursor endpoints: {notice}"
    );

    let exhausted = json!({
        "object": "list",
        "data": [{"id": "att-2"}, {"id": "att-1"}],
        "limit": 2,
        "next_cursor": Value::Null,
    });
    assert_eq!(
        truncation_notice(&exhausted, 0, Some(2)),
        None,
        "a full page with a null cursor is the definitive end of the listing"
    );

    let short_but_continuing = json!({
        "object": "list",
        "data": [{"id": "att-2"}],
        "limit": 50,
        "next_cursor": "1753500000:att-2",
    });
    let notice = truncation_notice(&short_but_continuing, 0, None)
        .expect("a live cursor means more rows even on a short page");
    assert!(notice.contains("more rows exist"), "{notice}");
}

/// A non-list response never produces a pagination notice.
#[test]
fn truncation_notice_ignores_non_list_documents() {
    assert_eq!(
        truncation_notice(&json!({"service": "ferrogate"}), 0, Some(10)),
        None
    );
}

/// Envelope metadata (notably `total`) must survive table rendering, otherwise
/// a truncated page looks identical to a complete one in the default format.
#[test]
fn render_table_keeps_list_envelope_metadata() {
    let body = json!({"object": "list", "data": [{"id": "x"}], "total": 500, "offset": 0});
    let table = render_table(&body).unwrap();
    assert!(table.contains("ID") && table.contains('x'));
    assert!(table.contains("total") && table.contains("500"), "{table}");
    assert!(table.contains("offset"), "{table}");
}

/// `--dry-run` is accepted by **every** mutating verb in the generated tree,
/// and parses into the flag the receipt echoes (issue #505).
///
/// This is the "accepted by every mutating verb" half of acceptance box 2. It
/// walks the whole registry rather than sampling, so a family that somehow
/// grew a verb outside the shared `ResourceArgs` would fail here instead of
/// being discovered by an operator.
#[test]
fn dry_run_is_accepted_by_every_mutating_verb() {
    let registry = registry();
    let command = build_ctl_command(&registry);
    let mut mutating = 0usize;
    for group in registry.groups() {
        for verb in &group.verbs {
            if !verb.is_mutating() {
                continue;
            }
            mutating += 1;
            // Three probe segments cover every addressing shape; extra
            // positionals are harmless to the parser, and the request builder
            // takes only the segments it needs.
            let matches = command
                .clone()
                .try_get_matches_from([
                    "ctl",
                    &group.name,
                    &verb.name,
                    "probe-0",
                    "probe-1",
                    "probe-2",
                    "--data",
                    "{}",
                    "--dry-run",
                ])
                .unwrap_or_else(|error| {
                    panic!("'{} {}' rejected --dry-run: {error}", group.name, verb.name)
                });
            let verb_matches = matches
                .subcommand()
                .unwrap()
                .1
                .subcommand()
                .unwrap()
                .1
                .clone();
            let resource = ResourceArgs::from_arg_matches(&verb_matches).unwrap();
            assert!(
                resource.dry_run,
                "'{} {}' parsed --dry-run as false",
                group.name, verb.name
            );
        }
    }
    assert!(
        mutating > 90,
        "expected 90+ mutating verbs in the tree, saw {mutating}"
    );
}

/// The flag defaults to false, so a mutation without it is a real mutation —
/// `dry_run` on the receipt cannot silently default to "safe".
#[test]
fn dry_run_defaults_to_false() {
    let registry = registry();
    let command = build_ctl_command(&registry);
    let matches = command
        .try_get_matches_from(["ctl", "projects", "create", "--data", "{}"])
        .expect("parses");
    let verb_matches = matches
        .subcommand()
        .unwrap()
        .1
        .subcommand()
        .unwrap()
        .1
        .clone();
    assert!(
        !ResourceArgs::from_arg_matches(&verb_matches)
            .unwrap()
            .dry_run
    );
}

/// Every registered verb resolves to a render gate whose arm agrees with the
/// declared effect. The binary-side companion to `ferrogate-cli-core`'s
/// registry enforcement test: it proves the *shipping tree* — not just the
/// library registry — has no ungated mutating verb.
#[test]
fn every_verb_in_the_shipping_tree_is_gated() {
    let registry = registry();
    let ctl = build_ctl_command(&registry);
    let mut gated = 0usize;
    for group in registry.groups() {
        let group_cmd = ctl
            .get_subcommands()
            .find(|command| command.get_name() == group.name)
            .expect("group in tree");
        for verb in &group.verbs {
            assert!(
                group_cmd
                    .get_subcommands()
                    .any(|command| command.get_name() == verb.name),
                "verb '{} {}' missing from the shipping tree",
                group.name,
                verb.name
            );
            match verb.render_gate() {
                RenderGate::Receipt(_) => assert!(
                    verb.is_mutating(),
                    "'{} {}' opened a receipt gate without being mutating",
                    group.name,
                    verb.name
                ),
                RenderGate::Bare(_) => assert!(
                    !verb.is_mutating(),
                    "'{} {}' is mutating but opened a bare render gate",
                    group.name,
                    verb.name
                ),
            }
            gated += 1;
        }
    }
    assert!(gated > 200, "expected 200+ gated verbs, saw {gated}");
}
