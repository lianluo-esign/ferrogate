// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Typed, non-bypassable egress posture for the Cloudflare container agent tier
//   (issue #471): `direct_public_egress = false` is enforced by construction (there is no
//   value of the type that expresses open internet), the governed allowlist rejects
//   wildcards and provider hosts, a provider denylist rides every governed start, and the
//   Worker's applied posture is verified against the requested one before a run proceeds.

//! **Enforced** egress posture for the Cloudflare Containers / Sandbox agent
//! tier (issue #471).
//!
//! # Why this type exists
//!
//! The value of routing a coding agent's LLM traffic back through FerroGate is
//! that 100% of tokens are metered, policied and audited. Before this module the
//! container tier expressed that intent as two loose fields on the start spec
//! (`enable_internet: bool` + `egress_allowlist: Vec<String>`), so a caller
//! could legally ask for `enable_internet = true` with an allowlist of
//! `["api.anthropic.com"]` — i.e. exactly the bypass the tether exists to
//! prevent. The isolation policy already said `direct_public_egress = false`;
//! nothing made that **true**.
//!
//! [`ContainerEgressPosture`] closes that: it is the ONLY way to describe the
//! network posture of a container start, and **no inhabitant of the type grants
//! direct public egress**. [`ContainerEgressPosture::direct_public_egress`]
//! returns `false` for every variant, unconditionally. There is no
//! `enable_internet` knob left to set.
//!
//! # What Cloudflare actually enforces (verified 2026-07-25)
//!
//! Per the Cloudflare Containers / Sandbox "Handle outbound traffic" docs
//! (see `docs/cloudflare-container-isolation.md` §"What Cloudflare actually
//! enforces" for the quotes and source URLs):
//!
//! * `enableInternet = false` **blocks public internet access at the platform
//!   layer**, not cooperatively: "only traffic you explicitly allow ... through
//!   `allowedHosts` or outbound handlers can leave the container". Only ports
//!   80/443 and DNS remain reachable, and DNS "only go[es] to Cloudflare's DNS
//!   servers". Traffic on any other port "is denied". The enforcement lives
//!   outside the container (a proxy on the same machine; the local-dev emulation
//!   applies `TPROXY` rules in the container's network namespace), so code
//!   running *inside* the container cannot switch it off.
//! * `allowedHosts` is "a deny-by-default allowlist" — "any host or IP not in
//!   the list is denied" (HTTP 520) — and grants egress to matching hosts even
//!   while `enableInternet` stays `false`.
//! * `deniedHosts` "blocks matching hosts unconditionally ... overriding
//!   everything else in the chain", so it survives an over-broad allowlist.
//!
//! That makes the tether a real network control, **provided the allowlist is
//! narrow**. The remaining, purely FerroGate-side risk is therefore
//! mis-configuration: an allowlist containing `*`, or a provider hostname. This
//! module makes both unrepresentable.
//!
//! # The three enforcement layers
//!
//! 1. **Type** — [`ContainerEgressPosture`] cannot express open egress; a
//!    [`GovernedEgressAllowlist`] cannot be constructed with a wildcard, a
//!    provider host, or a malformed host.
//! 2. **Wire** — every governed start carries [`PROVIDER_EGRESS_DENYLIST`] so
//!    the Worker applies `setDeniedHosts(...)`, which Cloudflare evaluates
//!    *first* and which overrides any allowlist. The Worker independently
//!    re-runs the same validation and rejects `enableInternet = true`
//!    unconditionally (422).
//! 3. **Attestation** — the Worker returns the posture it actually applied and
//!    [`EgressPostureAttestation::verify`] refuses to let the run proceed unless
//!    it matches the requested posture exactly. A Worker that silently ignored
//!    the allowlist fails the start instead of running untethered.
//!
//! What this does **not** buy is covered honestly in
//! [`crate::cloudflare_container_tether_audit`] (detection) and in the residual
//! risk section of `docs/cloudflare-container-isolation.md`.

use std::{error::Error, fmt};

use crate::isolation::IsolationNetworkPolicy;

/// Maximum length of a single allowlist host entry (DNS name limit).
const MAX_HOST_LEN: usize = 253;

/// Provider endpoints that a governed container agent must **never** reach
/// directly: every one of them is an LLM inference API whose traffic would be
/// unmetered, unpoliced and invisible to the audit trail if it bypassed the
/// gateway. Sent on every governed start so the Worker applies them via
/// `setDeniedHosts`, which Cloudflare evaluates before the allowlist and which
/// "overrides everything else in the chain" — so even an operator who somehow
/// widened the allowlist cannot reach a provider directly.
///
/// Entries may use the `*` glob Cloudflare's host matcher supports. FerroGate's
/// own allowlist validation matches them with [`host_matches_pattern`].
///
/// This list is a **denylist, and denylists are never complete** — it stops the
/// mainstream providers and every documented FerroGate-supported upstream, not a
/// determined adversary pointing at an unlisted relay. The load-bearing control
/// is the narrow allowlist (deny-by-default); this is defense in depth.
pub const PROVIDER_EGRESS_DENYLIST: &[&str] = &[
    "api.anthropic.com",
    "api.openai.com",
    "*.openai.azure.com",
    "generativelanguage.googleapis.com",
    "aiplatform.googleapis.com",
    "*.aiplatform.googleapis.com",
    "bedrock-runtime.*.amazonaws.com",
    "bedrock.*.amazonaws.com",
    "api.cohere.ai",
    "api.cohere.com",
    "api.mistral.ai",
    "api.groq.com",
    "api.deepseek.com",
    "api.x.ai",
    "api.together.xyz",
    "api.fireworks.ai",
    "api.perplexity.ai",
    "openrouter.ai",
    "*.openrouter.ai",
    "api.moonshot.cn",
    "dashscope.aliyuncs.com",
    "api.voyageai.com",
];

/// Why an egress posture was refused. Every variant is a **fail-closed** refusal
/// raised before any container is started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressPostureError {
    /// A tethered posture was requested with no hosts. A tether to nothing is a
    /// sealed container — say so explicitly with [`ContainerEgressPosture::Sealed`].
    EmptyAllowlist,
    /// The entry contains a `*` glob. A wildcard in an egress allowlist is an
    /// open-internet grant wearing an allowlist's clothes.
    Wildcard(String),
    /// The entry names an LLM provider endpoint (see [`PROVIDER_EGRESS_DENYLIST`]).
    /// Allowlisting a provider IS the bypass this tier exists to prevent.
    ProviderHost(String),
    /// The entry is not a bare host (scheme, path, port, credentials, whitespace,
    /// empty label, or over-long).
    MalformedHost(String),
    /// A policy or wire body asked for direct public egress. Structurally
    /// impossible for this tier.
    DirectPublicEgress(String),
    /// The Worker did not attest the posture it applied, or attested a posture
    /// that differs from the requested one.
    AttestationMismatch(String),
}

impl fmt::Display for EgressPostureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyAllowlist => write!(
                f,
                "a gateway-tethered egress posture requires at least one governed host; \
                 use the sealed posture for no egress"
            ),
            Self::Wildcard(h) => write!(
                f,
                "egress allowlist entry {h:?} contains a wildcard; a wildcard grant is \
                 indistinguishable from open public egress"
            ),
            Self::ProviderHost(h) => write!(
                f,
                "egress allowlist entry {h:?} names an LLM provider endpoint; the container \
                 tier must reach providers only through the governed gateway"
            ),
            Self::MalformedHost(h) => write!(
                f,
                "egress allowlist entry {h:?} is not a bare hostname or IP literal"
            ),
            Self::DirectPublicEgress(m) => {
                write!(f, "direct public egress is not available on this tier: {m}")
            }
            Self::AttestationMismatch(m) => {
                write!(
                    f,
                    "container egress posture was not attested as applied: {m}"
                )
            }
        }
    }
}

impl Error for EgressPostureError {}

/// A validated set of hosts the container may reach. Private field: the ONLY way
/// to obtain one is through the validating constructors, so an unvetted host can
/// never reach the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernedEgressAllowlist {
    hosts: Vec<String>,
}

impl GovernedEgressAllowlist {
    /// Tether the container to exactly one governed host — the FerroGate
    /// gateway. This is the posture the coding-agent tier runs in: the agent's
    /// LLM base URL points at this host and nothing else is reachable.
    pub fn tethered_to(gateway_host: impl AsRef<str>) -> Result<Self, EgressPostureError> {
        Self::try_new([gateway_host.as_ref()])
    }

    /// Build an allowlist from an arbitrary host set, validating every entry.
    /// Entries are normalized (trimmed, lowercased) and de-duplicated in stable
    /// order so the wire body — and the attestation comparison — are
    /// deterministic.
    pub fn try_new<I, S>(hosts: I) -> Result<Self, EgressPostureError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut normalized: Vec<String> = Vec::new();
        for host in hosts {
            let host = normalize_host(host.as_ref())?;
            if !normalized.contains(&host) {
                normalized.push(host);
            }
        }
        if normalized.is_empty() {
            return Err(EgressPostureError::EmptyAllowlist);
        }
        Ok(Self { hosts: normalized })
    }

    /// The validated hosts, in wire order.
    pub fn hosts(&self) -> &[String] {
        &self.hosts
    }
}

/// The network posture of a container start. **No variant grants direct public
/// egress** — that is the whole point of the type.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ContainerEgressPosture {
    /// No egress at all: `enableInternet = false` with no allowlist. Cloudflare
    /// denies every outbound connection (ports other than 80/443 are dropped;
    /// 80/443 have no permitted destination). The default.
    #[default]
    Sealed,
    /// Egress restricted to a validated governed host set — in practice the
    /// FerroGate gateway. Still `enableInternet = false`; Cloudflare grants the
    /// allowlisted hosts egress through the interception proxy.
    GatewayTethered(GovernedEgressAllowlist),
}

impl ContainerEgressPosture {
    /// The sealed (no egress) posture.
    pub fn sealed() -> Self {
        Self::Sealed
    }

    /// Tether egress to exactly one governed gateway host.
    pub fn tethered_to(gateway_host: impl AsRef<str>) -> Result<Self, EgressPostureError> {
        Ok(Self::GatewayTethered(GovernedEgressAllowlist::tethered_to(
            gateway_host,
        )?))
    }

    /// Tether egress to a validated host set.
    pub fn tethered<I, S>(hosts: I) -> Result<Self, EgressPostureError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Ok(Self::GatewayTethered(GovernedEgressAllowlist::try_new(
            hosts,
        )?))
    }

    /// Derive the posture from a managed-worker [`IsolationNetworkPolicy`].
    ///
    /// Fails closed on `direct_public_egress = true` (which
    /// [`crate::IsolationPolicy::validate`] also rejects) and on
    /// `governed_egress = false` — a container tier that cannot govern its
    /// egress must not be started at all rather than started wide open.
    pub fn from_network_policy(
        policy: &IsolationNetworkPolicy,
        gateway_host: Option<&str>,
    ) -> Result<Self, EgressPostureError> {
        if policy.direct_public_egress {
            return Err(EgressPostureError::DirectPublicEgress(
                "isolation network policy requested direct_public_egress = true".to_string(),
            ));
        }
        if !policy.governed_egress {
            return Err(EgressPostureError::DirectPublicEgress(
                "isolation network policy disabled governed_egress; the container tier has no \
                 ungoverned mode"
                    .to_string(),
            ));
        }
        match gateway_host.map(str::trim).filter(|h| !h.is_empty()) {
            Some(host) => Self::tethered_to(host),
            None => Ok(Self::Sealed),
        }
    }

    /// Always `false`. Kept as a method (rather than an absent field) so callers,
    /// evidence records and the wire body can state the guarantee explicitly.
    pub fn direct_public_egress(&self) -> bool {
        false
    }

    /// Hosts the container may reach; empty for [`Self::Sealed`].
    pub fn allowed_hosts(&self) -> &[String] {
        match self {
            Self::Sealed => &[],
            Self::GatewayTethered(list) => list.hosts(),
        }
    }

    /// Wire label recorded in the start body, the attestation and evidence.
    pub fn wire_label(&self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::GatewayTethered(_) => "gateway-tethered",
        }
    }

    /// The provider denylist applied alongside this posture.
    ///
    /// Only carried for the tethered posture: a sealed container's allowlist is
    /// the empty set, which Cloudflare treats as a deny-by-default gate refusing
    /// every host, so a denylist adds no restriction on top.
    ///
    /// This is NOT the same as "the sealed path touches nothing on the instance".
    /// It used to be, and that was a defect: instance names are reused, and
    /// `@cloudflare/containers` persists a runtime allowlist override to Durable
    /// Object storage, so a name that was tethered and is then started sealed kept
    /// the earlier grant while the Worker attested an empty allowlist. The Worker's
    /// sealed path now applies `setAllowedHosts([])` and `setDeniedHosts([])`
    /// explicitly. [`EgressPostureAttestation::verify`] compares the allowlist for
    /// equality (so `Sealed` still requires an attested `[]`) and the denylist as a
    /// superset (so a Worker denying more than we asked is accepted).
    pub fn denied_hosts(&self) -> &'static [&'static str] {
        match self {
            Self::Sealed => &[],
            Self::GatewayTethered(_) => PROVIDER_EGRESS_DENYLIST,
        }
    }
}

/// The posture the Worker reports it **actually applied** to the instance.
///
/// Returned by `POST /container/start`. The Rust client refuses to treat a start
/// as successful unless this is present and matches the requested posture, so a
/// Worker that ignored (or partially applied) the egress configuration surfaces
/// as a failed start rather than an untethered run.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct EgressPostureAttestation {
    /// MUST be `false`.
    #[serde(rename = "directPublicEgress")]
    pub direct_public_egress: bool,
    /// `sealed` or `gateway-tethered`.
    #[serde(default)]
    pub posture: String,
    /// Hosts the Worker passed to `setAllowedHosts` (empty when sealed).
    #[serde(rename = "allowedHosts", default)]
    pub allowed_hosts: Vec<String>,
    /// Hosts the Worker passed to `setDeniedHosts`.
    #[serde(rename = "deniedHosts", default)]
    pub denied_hosts: Vec<String>,
}

impl EgressPostureAttestation {
    /// Verify the applied posture against the requested one. Any divergence is a
    /// refusal, not a warning.
    pub fn verify(&self, requested: &ContainerEgressPosture) -> Result<(), EgressPostureError> {
        if self.direct_public_egress {
            return Err(EgressPostureError::DirectPublicEgress(
                "the Worker attested directPublicEgress = true for the started instance"
                    .to_string(),
            ));
        }
        if self.posture != requested.wire_label() {
            return Err(EgressPostureError::AttestationMismatch(format!(
                "requested {:?} but the Worker applied {:?}",
                requested.wire_label(),
                self.posture
            )));
        }
        if self.allowed_hosts != requested.allowed_hosts() {
            return Err(EgressPostureError::AttestationMismatch(format!(
                "requested allowlist {:?} but the Worker applied {:?}",
                requested.allowed_hosts(),
                self.allowed_hosts
            )));
        }
        // The denylist is checked as a SUPERSET, not for equality: a Worker that
        // denies MORE than FerroGate asked is strictly safer, and letting the
        // Worker keep its own (possibly newer) provider list is what stops the
        // two lists from having to be byte-identical forever. Every host
        // FerroGate asked to deny must, however, actually be denied.
        for expected in requested.denied_hosts() {
            if !self.denied_hosts.iter().any(|applied| applied == expected) {
                return Err(EgressPostureError::AttestationMismatch(format!(
                    "the Worker did not apply the provider denylist entry {expected:?}"
                )));
            }
        }
        Ok(())
    }
}

/// Normalize + validate one allowlist entry into a bare host.
///
/// Rejects anything that is not a plain hostname or IP literal: schemes, paths,
/// ports, credentials, whitespace, empty labels, over-long names — and, above
/// all, wildcards and provider endpoints.
fn normalize_host(raw: &str) -> Result<String, EgressPostureError> {
    let host = raw.trim().to_ascii_lowercase();
    if host.is_empty() {
        return Err(EgressPostureError::MalformedHost(raw.to_string()));
    }
    if host.contains('*') {
        return Err(EgressPostureError::Wildcard(raw.to_string()));
    }
    if host.len() > MAX_HOST_LEN {
        return Err(EgressPostureError::MalformedHost(raw.to_string()));
    }
    if host.contains("://")
        || host.contains('/')
        || host.contains(':')
        || host.contains('@')
        || host.contains('?')
        || host.contains('#')
        || host.chars().any(char::is_whitespace)
    {
        return Err(EgressPostureError::MalformedHost(raw.to_string()));
    }
    if host.starts_with('.') || host.ends_with('.') || host.contains("..") {
        return Err(EgressPostureError::MalformedHost(raw.to_string()));
    }
    let label_ok = |label: &str| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    };
    if !host.split('.').all(label_ok) {
        return Err(EgressPostureError::MalformedHost(raw.to_string()));
    }
    if PROVIDER_EGRESS_DENYLIST
        .iter()
        .any(|pattern| host_matches_pattern(&host, pattern))
    {
        return Err(EgressPostureError::ProviderHost(raw.to_string()));
    }
    Ok(host)
}

/// Match a concrete host against one denylist pattern, honoring the `*` glob
/// Cloudflare's host matcher supports (`*` matches any sequence of characters).
///
/// Implemented as a linear two-pointer glob so a pattern like
/// `bedrock-runtime.*.amazonaws.com` matches without regex or backtracking blowup.
pub fn host_matches_pattern(host: &str, pattern: &str) -> bool {
    let host = host.to_ascii_lowercase();
    let pattern = pattern.to_ascii_lowercase();
    let segments: Vec<&str> = pattern.split('*').collect();
    if segments.len() == 1 {
        return host == pattern;
    }
    // Anchor the first and last literal segments; the middle ones must appear in
    // order anywhere between them.
    let first = segments[0];
    let last = segments[segments.len() - 1];
    if !host.starts_with(first) || !host.ends_with(last) {
        return false;
    }
    if host.len() < first.len() + last.len() {
        return false;
    }
    let mut cursor = first.len();
    let end = host.len() - last.len();
    for segment in &segments[1..segments.len() - 1] {
        if segment.is_empty() {
            continue;
        }
        match host[cursor..end].find(segment) {
            Some(offset) => cursor += offset + segment.len(),
            None => return false,
        }
    }
    true
}

#[cfg(test)]
#[path = "cloudflare_container_egress_test.rs"]
mod tests;
