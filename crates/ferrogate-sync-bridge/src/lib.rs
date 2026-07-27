// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Token4AI Cloud, FerroGate AI Gateway -- the async-to-sync
// bridge lifted out of ferrogate-cli's gateway module (issue #553).

//! Running an async call from a synchronous call path.
//!
//! # Why this is a crate and not a module
//!
//! [`block_on_sync_bridge`] used to live in `ferrogate-cli`'s
//! `gateway/mod.rs`. Nothing about it is about a gateway: it takes a future
//! and returns its output. But because it was spelled
//! `crate::gateway::block_on_sync_bridge`, every one of `ferrogate-cli`'s
//! `state*.rs` control-plane files that needed to call a `.await`-ing
//! repository method from a synchronous thread had to name the data plane to
//! do it. Measured on `main` immediately before this crate existed, those
//! files mentioned `crate::gateway` 141 times, and 114 of those mentions --
//! 81% -- were this one function. That is what made the control plane and the
//! data plane look inseparable, and it was a naming accident, not a
//! dependency.
//!
//! The obvious alternative home was `ferrogate-core`, which nine crates
//! already depend on. It was rejected: `ferrogate-core` is 245 lines of pure
//! `serde` types, and its own admission rule (see its crate docs) is that a
//! thing belongs there when more than one layer must *agree on how to read
//! it*. A runtime mechanism is not something layers agree on how to read, and
//! hosting it would push tokio onto `ferrogate-billing`,
//! `ferrogate-policy`, `ferrogate-providers` and `ferrogate-routing`, none of
//! which have an async runtime today. A cargo feature would not have saved
//! them either, since features unify across a workspace build.
//!
//! # What this is *not*
//!
//! This is not a general invitation to block. Every caller here is a
//! synchronous path that exists for a reason recorded at the call site --
//! Pingora filter hooks, `std::thread::spawn` sweep loops, the Unix-socket
//! external-action authorizer. New async code should stay async.
//!
//! `ferrogate-storage` keeps its own private variant deliberately: it drives
//! the future on a process-wide shared multi-threaded runtime so that pooled
//! connection drivers survive across bridge calls (issue #248). That is a
//! different behaviour, not a duplicate, and it is not folded in here.

/// Drives `future` to completion from a synchronous caller.
///
/// If an ambient multi-threaded tokio runtime is already current, the future
/// runs on it under [`tokio::task::block_in_place`], so the worker thread is
/// handed back to the scheduler instead of being wedged. Otherwise -- no
/// runtime at all, or a `current_thread` one that would panic with "cannot
/// start a runtime from within a runtime" -- the future runs on a throwaway
/// `current_thread` runtime built on a dedicated scoped thread.
///
/// # Panics
///
/// Panics if the fallback runtime cannot be built, or if driving the future
/// panics (the panic is re-raised on the caller's thread by the scoped join).
pub fn block_on_sync_bridge<T>(future: impl std::future::Future<Output = T> + Send) -> T
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
