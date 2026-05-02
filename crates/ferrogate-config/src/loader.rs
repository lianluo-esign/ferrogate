use anyhow::{Context, Result};
use std::path::Path;

use crate::{parse_caddyfile, GatewayConfig};

pub fn is_caddyfile_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("Caddyfile"))
}

pub fn load_caddyfile(path: &Path) -> Result<GatewayConfig> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read Caddyfile {}", path.display()))?;
    parse_caddyfile(&raw, &path.display().to_string()).map_err(anyhow::Error::from)
}
