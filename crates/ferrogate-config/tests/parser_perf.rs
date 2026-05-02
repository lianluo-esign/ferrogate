use ferrogate_config::parse_caddyfile;
use std::time::{Duration, Instant};

#[test]
fn parses_small_reference_caddyfile_under_debug_smoke_budget() {
    let raw = include_str!("../../../Ferrogate/Caddyfile");
    let started = Instant::now();

    for _ in 0..1_000 {
        parse_caddyfile(raw, "Ferrogate/Caddyfile").unwrap();
    }

    assert!(
        started.elapsed() < Duration::from_secs(1),
        "small Caddyfile parser smoke exceeded 1s debug budget"
    );
}
