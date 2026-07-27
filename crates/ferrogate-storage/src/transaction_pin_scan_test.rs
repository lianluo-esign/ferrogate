// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.
//
// #480: the `search_path` pin audit run against KNOWN-BAD sources. The audit in
// `async_postgres_test.rs` can only ever report that the tree is clean; pointed
// at a clean tree, a scanner that matched nothing at all would look exactly the
// same. These tests are the other half: each one hands the scanner a source
// that MUST be rejected, so the audit is shown to have teeth before it is
// trusted to speak for 236 real call sites.

use crate::transaction_pin_scan_test_support::{
    code_only, is_control_plane_source, scan_source, TransactionOpener,
};

/// A transaction whose only mention of the pin helper is a comment inside the
/// method. Before #480 this passed the audit: the pin was matched as a
/// substring of the whole method window, comments included.
///
/// The comment sits BELOW the opening call on purpose. The window starts at the
/// opener, so a comment above it was never read either way and would prove
/// nothing about comment handling.
const PIN_NAMED_ONLY_IN_A_LINE_COMMENT: &str = r#"
impl Store {
    async fn record_evidence(&self) -> Result<()> {
        let transaction = client.transaction().await?;
        // Pinned by transaction_search_path_sql in the caller.
        transaction.execute(INSERT_EVIDENCE, &[]).await?;
        transaction.commit().await?;
        Ok(())
    }
}
"#;

/// The same method, differing ONLY in that the pin is a statement rather than a
/// comment. Without this companion, a rejection above would prove nothing --
/// the fixture could have been rejected for an unrelated reason.
const PIN_AS_A_STATEMENT: &str = r#"
impl Store {
    async fn record_evidence(&self) -> Result<()> {
        let transaction = client.transaction().await?;
        if let Some(sql) = self.async_pool.transaction_search_path_sql() {
            transaction.batch_execute(sql).await?;
        }
        transaction.execute(INSERT_EVIDENCE, &[]).await?;
        transaction.commit().await?;
        Ok(())
    }
}
"#;

#[test]
fn a_pin_named_only_in_a_line_comment_does_not_vouch_for_the_transaction() {
    let sites = scan_source("fixture.rs", PIN_NAMED_ONLY_IN_A_LINE_COMMENT);

    assert_eq!(sites.len(), 1, "{sites:?}");
    assert_eq!(sites[0].opener, TransactionOpener::Client);
    assert_eq!(sites[0].line, 4, "the site must name the opening call");
    assert!(
        !sites[0].pinned,
        "a comment that merely NAMES the pin helper vouched for an unpinned transaction (#480)",
    );
}

#[test]
fn a_pin_written_as_a_statement_vouches_for_the_same_transaction() {
    let sites = scan_source("fixture.rs", PIN_AS_A_STATEMENT);

    assert_eq!(sites.len(), 1, "{sites:?}");
    assert!(
        sites[0].pinned,
        "a real pin statement must still satisfy the audit, or the audit is unusable",
    );
}

/// Documentation on a nested item inside the window -- both spellings, because
/// `#[doc = "..."]` hides the marker in a string literal rather than a comment
/// and would survive a fix that only handled `//`.
#[test]
fn a_pin_named_only_in_a_doc_comment_or_doc_attribute_does_not_vouch() {
    let doc_comment = r#"
impl Store {
    async fn record_evidence(&self) -> Result<()> {
        let transaction = client.transaction().await?;
        /// Written by transaction_search_path_sql.
        struct EvidenceRow;
        transaction.execute(INSERT_EVIDENCE, &[]).await?;
        Ok(())
    }
}
"#;
    let doc_attribute = r#"
impl Store {
    async fn record_evidence(&self) -> Result<()> {
        let transaction = client.transaction().await?;
        #[doc = "Written by transaction_search_path_sql."]
        struct EvidenceRow;
        transaction.execute(INSERT_EVIDENCE, &[]).await?;
        Ok(())
    }
}
"#;

    for source in [doc_comment, doc_attribute] {
        let sites = scan_source("fixture.rs", source);
        assert_eq!(sites.len(), 1, "{sites:?}");
        assert!(
            !sites[0].pinned,
            "documentation vouched for an unpinned transaction: {source}"
        );
    }
}

#[test]
fn a_pin_named_only_in_a_block_comment_does_not_vouch() {
    let source = r#"
impl Store {
    async fn record_evidence(&self) -> Result<()> {
        let transaction = client.transaction().await?;
        /* transaction_search_path_sql runs in the caller. */
        transaction.execute(INSERT_EVIDENCE, &[]).await?;
        Ok(())
    }
}
"#;

    let sites = scan_source("fixture.rs", source);

    assert_eq!(sites.len(), 1, "{sites:?}");
    assert!(
        !sites[0].pinned,
        "a block comment vouched for an unpinned transaction"
    );
}

#[test]
fn a_pin_named_only_inside_a_sql_literal_does_not_vouch() {
    let source = r#"
impl Store {
    async fn record_evidence(&self) -> Result<()> {
        let transaction = client.transaction().await?;
        transaction.execute("/* transaction_search_path_sql */ INSERT ...", &[]).await?;
        Ok(())
    }
}
"#;

    let sites = scan_source("fixture.rs", source);

    assert_eq!(sites.len(), 1, "{sites:?}");
    assert!(
        !sites[0].pinned,
        "a SQL comment vouched for an unpinned transaction"
    );
}

/// The `.build_transaction().read_only(true).start()` idiom, which the pre-#480
/// scan never counted at all: it matched only the literal `client.transaction()`.
/// A new site in this shape could have shipped unpinned with the audit green.
#[test]
fn an_unpinned_build_transaction_site_is_scanned_and_rejected() {
    let source = r#"
impl Store {
    async fn read_authorization(&self) -> Result<()> {
        let transaction = client
            .build_transaction()
            .read_only(true)
            .start()
            .await?;
        transaction.query(SELECT_AUTHORIZATION, &[]).await?;
        Ok(())
    }
}
"#;

    let sites = scan_source("fixture.rs", source);

    assert_eq!(
        sites.len(),
        1,
        "the builder idiom must be counted as a transaction: {sites:?}"
    );
    assert_eq!(sites[0].opener, TransactionOpener::Builder);
    assert_eq!(
        sites[0].line, 5,
        "the site must name the `build_transaction()` call"
    );
    assert!(
        !sites[0].pinned,
        "an unpinned read-only transaction was accepted"
    );
}

/// The shape `mcp_identity.rs` actually uses today, so the new coverage does
/// not turn a correct site red.
#[test]
fn a_pinned_build_transaction_site_is_accepted() {
    let source = r#"
impl Store {
    async fn read_authorization(&self) -> Result<()> {
        let transaction = client
            .build_transaction()
            .read_only(true)
            .start()
            .await?;
        if let Some(sql) = self.async_pool.transaction_search_path_sql() {
            transaction.batch_execute(sql).await?;
        }
        transaction.query(SELECT_AUTHORIZATION, &[]).await?;
        Ok(())
    }
}
"#;

    let sites = scan_source("fixture.rs", source);

    assert_eq!(sites.len(), 1, "{sites:?}");
    assert_eq!(sites[0].opener, TransactionOpener::Builder);
    assert!(sites[0].pinned);
}

/// Blanking comments is only safe if it knows what a comment IS. `//` inside a
/// URL and `/*` inside a SQL tag are ordinary string content; a scanner that
/// blanked from them would erase real pin statements and report false unpinned
/// sites -- the failure mode that makes people delete a guard rather than fix
/// the code.
#[test]
fn string_content_that_looks_like_a_comment_does_not_hide_the_pin() {
    let url_in_a_string = r#"
impl Store {
    async fn record_evidence(&self) -> Result<()> {
        let transaction = client.transaction().await?;
        let source = "https://token4ai.cloud"; let pin = self.async_pool.transaction_search_path_sql();
        transaction.batch_execute(pin.unwrap_or_default()).await?;
        Ok(())
    }
}
"#;
    let unclosed_sql_tag = r#"
impl Store {
    async fn record_evidence(&self) -> Result<()> {
        let transaction = client.transaction().await?;
        let tag = "/* ferrogate:evidence";
        let pin = self.async_pool.transaction_search_path_sql();
        transaction.batch_execute(pin.unwrap_or_default()).await?;
        Ok(())
    }
}
"#;
    // `lib.rs` really does quote identifiers with `replace('"', ...)`. Read as
    // a bare quote, that char literal opens a string that runs on and swallows
    // every statement after it -- including the pin.
    let quote_char_literal = r#"
impl Store {
    async fn record_evidence(&self) -> Result<()> {
        let transaction = client.transaction().await?;
        let quoted = identifier.replace('"', "*"); let pin = self.async_pool.transaction_search_path_sql();
        transaction.batch_execute(pin.unwrap_or_default()).await?;
        Ok(())
    }
}
"#;

    for source in [url_in_a_string, unclosed_sql_tag, quote_char_literal] {
        let sites = scan_source("fixture.rs", source);
        assert_eq!(sites.len(), 1, "{sites:?}");
        assert!(
            sites[0].pinned,
            "a genuinely pinned transaction was reported unpinned: {source}"
        );
    }
}

#[test]
fn blanking_preserves_line_structure_so_reported_lines_stay_true() {
    let source = "let a = 1; // https://token4ai.cloud\n/* two\nlines */\nlet b = \"x\\\n y\";\n";

    let blanked = code_only(source);

    assert_eq!(blanked.lines().count(), source.lines().count());
    for (blanked_line, source_line) in blanked.lines().zip(source.lines()) {
        assert_eq!(
            blanked_line.chars().count(),
            source_line.chars().count(),
            "{blanked:?}"
        );
    }
    assert!(blanked.contains("let a = 1;"));
    assert!(!blanked.contains("token4ai"), "{blanked:?}");
    assert!(!blanked.contains("two"), "{blanked:?}");
}

#[test]
fn a_commented_out_transaction_is_not_a_transaction() {
    let source = r#"
impl Store {
    async fn record_evidence(&self) -> Result<()> {
        // let transaction = client.transaction().await?;
        Ok(())
    }
}
"#;

    assert!(scan_source("fixture.rs", source).is_empty());
}

#[test]
fn sources_without_transactions_report_nothing() {
    assert!(scan_source("fixture.rs", "").is_empty());
    assert!(scan_source("fixture.rs", "fn main() {}\n").is_empty());
}

#[test]
fn only_control_plane_sources_are_in_scope() {
    assert!(is_control_plane_source("guardrail_evidence.rs"));
    assert!(is_control_plane_source("mcp_identity.rs"));
    // Test modules open throwaway transactions against throwaway schemas, and
    // this scanner's own support module spells the idioms out as literals.
    assert!(!is_control_plane_source("async_postgres_test.rs"));
    assert!(!is_control_plane_source("schema_routing_test_support.rs"));
    assert!(!is_control_plane_source(
        "transaction_pin_scan_test_support.rs"
    ));
    assert!(!is_control_plane_source("README.md"));
}
