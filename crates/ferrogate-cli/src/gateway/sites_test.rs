// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-19
// description: Unit tests for the static-site serve-mode pure logic (issue
// #258) -- path/index resolution, SPA fallback, content-type guessing, and the
// minimal zip reader (stored + deflate, path-traversal rejection, zip-bomb
// guard) -- kept out of the async gateway handler so they run without a live
// database.

use std::io::Write;

use super::*;

fn entry(path: &str) -> SiteFileEntry {
    SiteFileEntry {
        path: path.to_string(),
        content_type: guess_site_content_type(path),
        content_hash: String::new(),
        size_bytes: 0,
    }
}

fn manifest(files: &[&str], spa_fallback: bool) -> SiteManifest {
    SiteManifest {
        site: "demo".to_string(),
        bundle_version: "1.0.0".to_string(),
        public: false,
        spa_fallback,
        cache_control: None,
        files: files.iter().map(|path| entry(path)).collect(),
        created_at_unix: 0,
        updated_at_unix: 0,
    }
}

/// Builds a real ZIP archive so the parser is exercised end-to-end. When
/// `deflate` is set, entries are raw-deflate compressed (method 8), otherwise
/// stored (method 0).
fn build_zip(entries: &[(&str, &[u8])], deflate: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    let mut offsets = Vec::new();

    for (name, data) in entries {
        let offset = out.len() as u32;
        offsets.push(offset);
        let name_bytes = name.as_bytes();
        let (method, stored): (u16, Vec<u8>) = if deflate {
            let mut encoder =
                flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(data).unwrap();
            (8, encoder.finish().unwrap())
        } else {
            (0, data.to_vec())
        };

        // Local file header.
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&method.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // mod time
        out.extend_from_slice(&0u16.to_le_bytes()); // mod date
        out.extend_from_slice(&0u32.to_le_bytes()); // crc32 (not validated)
        out.extend_from_slice(&(stored.len() as u32).to_le_bytes()); // compressed
        out.extend_from_slice(&(data.len() as u32).to_le_bytes()); // uncompressed
        out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(&stored);

        // Central directory header.
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes()); // version made by
        central.extend_from_slice(&20u16.to_le_bytes()); // version needed
        central.extend_from_slice(&0u16.to_le_bytes()); // flags
        central.extend_from_slice(&method.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // mod time
        central.extend_from_slice(&0u16.to_le_bytes()); // mod date
        central.extend_from_slice(&0u32.to_le_bytes()); // crc32
        central.extend_from_slice(&(stored.len() as u32).to_le_bytes()); // compressed
        central.extend_from_slice(&(data.len() as u32).to_le_bytes()); // uncompressed
        central.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra len
        central.extend_from_slice(&0u16.to_le_bytes()); // comment len
        central.extend_from_slice(&0u16.to_le_bytes()); // disk number start
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        central.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name_bytes);
    }

    let cd_offset = out.len() as u32;
    let cd_size = central.len() as u32;
    out.extend_from_slice(&central);

    // End-of-central-directory record.
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // disk number
    out.extend_from_slice(&0u16.to_le_bytes()); // disk with cd
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes()); // entries this disk
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes()); // total entries
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len
    out
}

#[test]
fn directory_paths_resolve_to_index_html() {
    let manifest = manifest(&["index.html", "style.css", "docs/readme.md"], false);
    // Root ("" from a trailing-slash serve path) -> index.html.
    assert_eq!(resolve_site_file(&manifest, "").unwrap().path, "index.html");
    assert_eq!(
        resolve_site_file(&manifest, "/").unwrap().path,
        "index.html"
    );
    // Exact file hits.
    assert_eq!(
        resolve_site_file(&manifest, "style.css").unwrap().path,
        "style.css"
    );
    assert_eq!(
        resolve_site_file(&manifest, "docs/readme.md").unwrap().path,
        "docs/readme.md"
    );
}

#[test]
fn subdirectory_without_trailing_slash_resolves_to_its_index() {
    let manifest = manifest(&["index.html", "docs/index.html"], false);
    assert_eq!(
        resolve_site_file(&manifest, "docs").unwrap().path,
        "docs/index.html"
    );
    assert_eq!(
        resolve_site_file(&manifest, "docs/").unwrap().path,
        "docs/index.html"
    );
}

#[test]
fn missing_file_is_none_without_spa_fallback() {
    let manifest = manifest(&["index.html"], false);
    assert!(resolve_site_file(&manifest, "app/route").is_none());
}

#[test]
fn spa_fallback_serves_root_index_for_unknown_paths() {
    let manifest = manifest(&["index.html", "style.css"], true);
    assert_eq!(
        resolve_site_file(&manifest, "app/deep/route").unwrap().path,
        "index.html"
    );
    // A real file still wins over the fallback.
    assert_eq!(
        resolve_site_file(&manifest, "style.css").unwrap().path,
        "style.css"
    );
}

#[test]
fn content_types_are_guessed_from_extension() {
    assert_eq!(
        guess_site_content_type("index.html"),
        "text/html; charset=utf-8"
    );
    assert_eq!(
        guess_site_content_type("style.css"),
        "text/css; charset=utf-8"
    );
    assert_eq!(
        guess_site_content_type("docs/readme.md"),
        "text/markdown; charset=utf-8"
    );
    assert_eq!(
        guess_site_content_type("app.js"),
        "application/javascript; charset=utf-8"
    );
    assert_eq!(guess_site_content_type("data.json"), "application/json");
    assert_eq!(guess_site_content_type("logo.svg"), "image/svg+xml");
    assert_eq!(guess_site_content_type("noext"), "application/octet-stream");
}

#[test]
fn is_zip_archive_detects_the_magic() {
    let zip = build_zip(&[("index.html", b"<h1>hi</h1>")], false);
    assert!(is_zip_archive(&zip));
    assert!(!is_zip_archive(b"<html>not a zip</html>"));
}

#[test]
fn unzip_stored_entries_round_trips() {
    let zip = build_zip(
        &[
            ("index.html", b"<h1>home</h1>"),
            ("style.css", b"body{color:red}"),
            ("docs/readme.md", b"# docs"),
        ],
        false,
    );
    let mut files = unzip_archive(&zip, MAX_SITE_UNPACKED_BYTES).unwrap();
    files.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(files.len(), 3);
    assert_eq!(files[0], ("docs/readme.md".to_string(), b"# docs".to_vec()));
    assert_eq!(
        files[1],
        ("index.html".to_string(), b"<h1>home</h1>".to_vec())
    );
    assert_eq!(
        files[2],
        ("style.css".to_string(), b"body{color:red}".to_vec())
    );
}

#[test]
fn unzip_deflated_entries_round_trips() {
    let payload = "the quick brown fox ".repeat(64);
    let zip = build_zip(&[("index.html", payload.as_bytes())], true);
    let files = unzip_archive(&zip, MAX_SITE_UNPACKED_BYTES).unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].0, "index.html");
    assert_eq!(files[0].1, payload.as_bytes());
}

#[test]
fn unzip_skips_directory_entries() {
    let zip = build_zip(&[("docs/", b""), ("docs/readme.md", b"hi")], false);
    let files = unzip_archive(&zip, MAX_SITE_UNPACKED_BYTES).unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].0, "docs/readme.md");
}

#[test]
fn unzip_rejects_path_traversal() {
    let zip = build_zip(&[("../escape.txt", b"x")], false);
    let error = unzip_archive(&zip, MAX_SITE_UNPACKED_BYTES).unwrap_err();
    assert!(error.contains("unsafe zip entry path"), "{error}");
}

#[test]
fn unzip_enforces_the_unpacked_size_cap() {
    let zip = build_zip(&[("big.txt", &vec![b'a'; 4096])], false);
    let error = unzip_archive(&zip, 1024).unwrap_err();
    assert!(error.contains("more than"), "{error}");
}

#[test]
fn unzip_rejects_non_zip_bytes() {
    let error = unzip_archive(b"not a zip at all", MAX_SITE_UNPACKED_BYTES).unwrap_err();
    assert!(error.contains("not a valid zip archive"), "{error}");
}

#[test]
fn manifest_serde_round_trips() {
    let manifest = SiteManifest {
        site: "demo".to_string(),
        bundle_version: "2.0.0".to_string(),
        public: true,
        spa_fallback: true,
        cache_control: Some("public, max-age=60".to_string()),
        files: vec![entry("index.html")],
        created_at_unix: 111,
        updated_at_unix: 222,
    };
    let bytes = serde_json::to_vec(&manifest).unwrap();
    let parsed: SiteManifest = serde_json::from_slice(&bytes).unwrap();
    assert!(parsed.public);
    assert!(parsed.spa_fallback);
    assert_eq!(parsed.cache_control.as_deref(), Some("public, max-age=60"));
    assert_eq!(parsed.files.len(), 1);
}

#[test]
fn header_flag_parses_truthy_values() {
    let mut headers = http::HeaderMap::new();
    headers.insert("x-site-public", "true".parse().unwrap());
    assert!(header_flag(&headers, "x-site-public"));
    headers.insert("x-site-public", "1".parse().unwrap());
    assert!(header_flag(&headers, "x-site-public"));
    headers.insert("x-site-public", "false".parse().unwrap());
    assert!(!header_flag(&headers, "x-site-public"));
    assert!(!header_flag(&headers, "x-site-missing"));
}
