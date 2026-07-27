// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Pure artifact-registry resolution logic for /v1/assets/*
// (issue #260) -- channel (`latest`/`stable`/`canary` + free-form tag) and
// semver-range resolution to a concrete version, plus platform/arch variant
// selection. Kept free of any Session/IO so the resolution rules are unit
// tested directly against `StoredAsset`/`StoredAssetChannel` slices, with the
// gateway handler doing only the storage fetch + HTTP wiring around them.

use ferrogate_storage::{StoredAsset, StoredAssetChannel};

/// How a pull reference (the third path segment) resolved to a concrete
/// version -- surfaced back to the client as an `x-ferrogate-asset-resolved`
/// header so an agent can see whether it got an exact pin, a channel, or a
/// range match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VersionResolution {
    Exact,
    Channel(String),
    Range(String),
}

impl VersionResolution {
    pub(crate) fn header_value(&self, version: &str) -> String {
        match self {
            VersionResolution::Exact => format!("exact={version}"),
            VersionResolution::Channel(channel) => format!("channel={channel};version={version}"),
            VersionResolution::Range(range) => format!("range={range};version={version}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedVersion {
    pub version: String,
    /// `true` only for an exact pull of a yanked version (which still
    /// succeeds, with a deprecation warning). Channel/range resolution never
    /// returns a yanked version.
    pub yanked: bool,
    pub how: VersionResolution,
}

/// Distinct versions present in `assets`, each tagged with whether it is
/// yanked. A version is considered yanked when any of its variant rows is
/// yanked (the yank handler marks every variant of a version together).
/// First-seen order is preserved for determinism.
fn version_states(assets: &[StoredAsset]) -> Vec<(String, bool)> {
    let mut out: Vec<(String, bool)> = Vec::new();
    for asset in assets {
        if let Some(entry) = out
            .iter_mut()
            .find(|(version, _)| version == &asset.version)
        {
            entry.1 = entry.1 || asset.yanked;
        } else {
            out.push((asset.version.clone(), asset.yanked));
        }
    }
    out
}

/// Highest non-yanked version that parses as semver and (when `req` is set)
/// satisfies the range. Versions that do not parse as semver are ignored --
/// range/channel resolution is defined only over semver-shaped versions.
fn highest_matching(
    versions: &[(String, bool)],
    req: Option<&semver::VersionReq>,
) -> Option<String> {
    let mut best: Option<(semver::Version, String)> = None;
    for (version, yanked) in versions {
        if *yanked {
            continue;
        }
        let Ok(parsed) = semver::Version::parse(version) else {
            continue;
        };
        if let Some(req) = req {
            if !req.matches(&parsed) {
                continue;
            }
        }
        let replace = match &best {
            Some((current, _)) => parsed > *current,
            None => true,
        };
        if replace {
            best = Some((parsed, version.clone()));
        }
    }
    best.map(|(_, version)| version)
}

/// Resolve a pull reference to a concrete version.
///
/// Precedence: (1) an exact version match always wins and is served even when
/// yanked (exact pins keep working, cargo-style); (2) a channel pointer --
/// explicit, or the implicit `latest` -- resolving to its target unless that
/// target is yanked/missing, in which case it falls back to the highest
/// non-yanked version; (3) a semver range. `None` means the reference could
/// not be resolved (HTTP 404).
pub(crate) fn resolve_version(
    assets: &[StoredAsset],
    channels: &[StoredAssetChannel],
    reference: &str,
) -> Option<ResolvedVersion> {
    let versions = version_states(assets);
    if versions.is_empty() {
        return None;
    }

    // 1. Exact version -- yanked-inclusive.
    if let Some((version, yanked)) = versions.iter().find(|(version, _)| version == reference) {
        return Some(ResolvedVersion {
            version: version.clone(),
            yanked: *yanked,
            how: VersionResolution::Exact,
        });
    }

    // 2. Channel pointer (explicit) or the implicit `latest` channel.
    let explicit = channels.iter().find(|channel| channel.channel == reference);
    if explicit.is_some() || reference == "latest" {
        if let Some(channel) = explicit {
            if let Some((version, yanked)) = versions
                .iter()
                .find(|(version, _)| version == &channel.version)
            {
                if !*yanked {
                    return Some(ResolvedVersion {
                        version: version.clone(),
                        yanked: false,
                        how: VersionResolution::Channel(reference.to_string()),
                    });
                }
            }
        }
        // Implicit latest, or fallback when the explicit pointer is
        // missing/yanked: newest non-yanked version.
        if let Some(version) = highest_matching(&versions, None) {
            return Some(ResolvedVersion {
                version,
                yanked: false,
                how: VersionResolution::Channel(reference.to_string()),
            });
        }
        return None;
    }

    // 3. Semver range (`^1.2`, `~2.0`, `1`, ...).
    if let Ok(req) = semver::VersionReq::parse(reference) {
        if let Some(version) = highest_matching(&versions, Some(&req)) {
            return Some(ResolvedVersion {
                version,
                yanked: false,
                how: VersionResolution::Range(reference.to_string()),
            });
        }
    }

    None
}

/// Outcome of selecting a platform/arch variant for a resolved version.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum VariantChoice<'a> {
    Selected(&'a StoredAsset),
    /// A specific platform was requested but no such variant exists, or the
    /// version carries no artifacts at all.
    NotFound,
    /// Multiple variants exist, none is the default, and the caller supplied
    /// no platform hint -- the client must disambiguate with `?platform=`.
    Ambiguous,
}

/// Select the artifact for a resolved version. With an explicit `requested`
/// platform, only an exact variant match is served. Without one, the default
/// (empty-variant) artifact is preferred; failing that, a lone variant is
/// served; more than one variant is ambiguous.
pub(crate) fn select_variant<'a>(
    rows: &[&'a StoredAsset],
    requested: Option<&str>,
) -> VariantChoice<'a> {
    if let Some(platform) = requested {
        return match rows.iter().find(|row| row.variant == platform) {
            Some(row) => VariantChoice::Selected(row),
            None => VariantChoice::NotFound,
        };
    }
    if let Some(row) = rows.iter().find(|row| row.variant.is_empty()) {
        return VariantChoice::Selected(row);
    }
    match rows {
        [only] => VariantChoice::Selected(only),
        [] => VariantChoice::NotFound,
        _ => VariantChoice::Ambiguous,
    }
}

#[cfg(test)]
#[path = "asset_registry_test.rs"]
mod asset_registry_test;
