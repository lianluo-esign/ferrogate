// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Cross-cutting helpers shared by every concern module: sync/async
//! bridging, id/secret generation, password hashing, and constant-time
//! comparison.

use anyhow::anyhow;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use std::time::{SystemTime, UNIX_EPOCH};

/// Bridges an async storage call into this crate's fully synchronous
/// request path (issue #221): `serve`'s connection loop spawns a plain
/// `std::thread::spawn` per connection with no tokio runtime anywhere in the
/// chain, and admin-console/SCIM handlers are shared by ~15 call sites that
/// would all need to become `async fn` (cascading into `route_request`,
/// `handle_connection`, and `serve`'s accept loop) to avoid this. Mirrors
/// `ferrogate-cli`'s `gateway::block_on_sync_bridge` -- same
/// `Handle::try_current()` + multi-thread-flavor check, falling back to a
/// dedicated `current_thread` runtime, kept as a small local copy since the
/// two crates don't share this kind of helper.
pub(crate) fn block_on_sync_bridge<T>(future: impl std::future::Future<Output = T> + Send) -> T
where
    T: Send,
{
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
            return tokio::task::block_in_place(|| handle.block_on(future));
        }
    }
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("sync-bridge runtime should build")
                    .block_on(future)
            })
            .join()
            .expect("sync-bridge runtime thread should not panic")
    })
}

/// Generates an Argon2 hash of a random, immediately-discarded secret so a
/// SCIM-provisioned account (which authenticates via SSO, not a FerroGate
/// password -- see issue #160) has no usable password.
pub(crate) fn unusable_password_hash() -> anyhow::Result<String> {
    hash_password(&generate_random_hex(32)?)
}

pub(crate) fn generate_refresh_token_secret() -> anyhow::Result<String> {
    generate_random_hex(32)
}

pub(crate) fn generate_random_hex(byte_len: usize) -> anyhow::Result<String> {
    let mut buffer = vec![0_u8; byte_len];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut buffer)
        .map_err(|_| anyhow!("failed to generate secure random bytes"))?;
    Ok(encode_hex(&buffer))
}

pub(crate) fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| anyhow!("failed to hash password: {error}"))
}

pub(crate) fn verify_password(password: &str, hash: &str) -> bool {
    let Ok(parsed_hash) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

pub(crate) fn next_id(kind: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!("{kind}-{nanos}-{}", std::process::id())
}

/// Derive a URL-safe slug from an operator-supplied organization name, with a
/// short unique suffix appended so it satisfies the `tenants.slug` UNIQUE
/// constraint without a create-then-retry-on-conflict loop.
///
/// The suffix is a hash of `unique_seed` rather than a positional substring
/// of it: `unique_seed` is normally a `next_id()`-style
/// `"{kind}-{nanos}-{pid}"` string, and naively slicing its last N characters
/// lands on the constant `pid` segment (not the per-call `nanos` segment),
/// so every registration sharing an organization name within one process
/// lifetime collided on the exact same slug and got a permanent 409/503.
pub(crate) fn slugify_with_suffix(name: &str, unique_seed: &str) -> String {
    let normalized: String = name
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '-'
            }
        })
        .collect();
    let base = normalized
        .split('-')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    let base = if base.is_empty() {
        "org".to_string()
    } else {
        base
    };
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    std::hash::Hash::hash(unique_seed, &mut hasher);
    let suffix = format!("{:016x}", std::hash::Hasher::finish(&hasher));
    format!("{base}-{suffix}")
}

pub(crate) fn is_valid_email(email: &str) -> bool {
    let mut parts = email.splitn(2, '@');
    let (Some(local), Some(domain)) = (parts.next(), parts.next()) else {
        return false;
    };
    !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
}

pub(crate) fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}
