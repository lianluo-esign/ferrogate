// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: The gateway's HTTP adapter over the shared #514 lifecycle gate.
//
// The decision, the vocabulary and the hierarchy WALK all live in
// `ferrogate_storage::lifecycle_gate` -- the crate that owns the rows -- so
// that every credential-minting caller can reach them. That relocation is not
// cosmetic: while this module owned the decision, `ferrogate-auth-service`'s
// admin-console login/register/SSO paths could not call it and kept minting
// live gateway keys under a suspended tenant. All that is left here is the
// mapping from the shared refusal to this crate's `AuthError`, which is how
// every other refusal in the gateway is rendered.
//
// #553 stage 3b-0 moved this module here rather than leaving it in
// `ferrogate-cli`, because the orphan rule stopped permitting the conversion
// there the moment `AuthError` became `ferrogate-gateway`'s type while
// `LifecycleGateError` stayed `ferrogate-storage`'s. The module is
// private -- it publishes no items, only this impl, which is visible wherever
// both types are. Its former `pub(crate) use` of `LifecycleSeam`/`TenancyRefs`
// went away with it: those are `ferrogate_storage`'s names and callers now say
// so.

use http::StatusCode;

use ferrogate_storage::LifecycleGateError;

impl From<LifecycleGateError> for crate::auth::AuthError {
    fn from(error: LifecycleGateError) -> Self {
        crate::auth::AuthError {
            // `http_status()` is a `u16` on the storage side (the storage crate
            // has no HTTP dependency); the fallback can only be reached if a
            // future variant returns a non-status number, and defaulting to 403
            // keeps a refusal a refusal rather than turning it into a 200.
            status: StatusCode::from_u16(error.http_status()).unwrap_or(StatusCode::FORBIDDEN),
            code: error.code(),
            message: error.message(),
        }
    }
}

#[cfg(test)]
#[path = "lifecycle_gate_test.rs"]
mod lifecycle_gate_test;
