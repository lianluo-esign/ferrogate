// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Admission control for the buffering, bucket-backed read path
// (issue #529) -- an aggregate in-flight-byte budget that queues briefly and
// then sheds with a typed refusal, so peak gateway memory for asset reads is an
// enforced number rather than a documented multiplication.

//! # Why a byte budget rather than a request-count semaphore
//!
//! Issue #259 gave every buffering read ONE per-operation bound
//! (`[asset_bucket].max_gateway_buffer_bytes`, default 10 MiB) enforced at one
//! chokepoint. That made peak memory exactly
//! `max_gateway_buffer_bytes x concurrent bucket-backed reads` -- and nothing
//! bounded the second factor. This module bounds it.
//!
//! The ceiling is expressed in BYTES, not in requests, for two reasons:
//!
//! 1. A count sized for 10 MiB reads is wrong the moment the per-operation
//!    budget is retuned. `max_total_gateway_buffer_bytes` keeps meaning the
//!    same thing (a memory ceiling) when `max_gateway_buffer_bytes` changes.
//! 2. Reads are charged what they will actually hold -- the size the registry
//!    row declares -- not the worst case. A static site serving 4 KiB files is
//!    charged 4 KiB apiece, so the budget throttles the requests that threaten
//!    memory and stays out of the way of the ones that do not. A count-based
//!    cap cannot tell those apart.
//!
//! # Queue, then shed
//!
//! Admission first tries to take the charge without waiting. If the budget is
//! committed it waits, but only for a **bounded** interval
//! (`[asset_bucket].buffer_admission_wait_ms`, default 250 ms), which absorbs
//! bursts without turning overload into an unbounded queue. When the wait
//! expires the read is refused with a typed 503 that names the condition; it is
//! never served truncated and never left waiting silently.
//!
//! The queue is FIFO, so a large read at the head cannot be starved by a stream
//! of small ones -- but that takes more than tokio's semaphore being FIFO among
//! its *waiters*. `try_acquire_many_owned` does not consult the wait queue at
//! all, so the no-wait fast path would let every newly arriving 4 KiB read
//! barge past a 10 MiB read already queued, which under sustained small-read
//! load burns the large read's whole wait and sheds it. [`Self::waiting`]
//! counts queued readers and the fast path is skipped while it is non-zero, so
//! the documented property is the enforced one.
//!
//! # The permit outlives the RESPONSE, not the transport read
//!
//! [`BufferedObject`] pairs the bytes with the permit that authorized them, and
//! the permit is released when the bytes are dropped -- not when the bucket GET
//! returns. This is the difference between a real ceiling and a rate limiter:
//! if the permit were released at the end of the read, N requests could each
//! pass admission in turn and then hold their buffers concurrently through
//! hashing, base64 encoding and the response write, which is exactly the
//! aggregate this exists to bound.
//!
//! "Dropped" means dropped by the *response writer*, on all four read surfaces:
//!
//! - the registry pull and the static-site serve bind the permit to a local
//!   that outlives `write_cacheable_response`;
//! - the `fetch_asset` tool and MCP `resources/read` do not write the bytes
//!   themselves -- they inline a JSON copy of the object into a response value
//!   that some other code writes -- so the permit is parked ON that value as a
//!   [`ResponseBufferBudget`] and released when the response is dropped, after
//!   the socket write.
//!
//! Issue #529's first round released the permit at the end of the match arm on
//! those two surfaces while a full second copy of the object travelled on
//! inside the JSON. Resident asset bytes then grew with the number of stalled
//! clients rather than with the ceiling.
//!
//! # What an inlining surface is charged
//!
//! The two JSON surfaces do not hold one copy of the object, they hold up to
//! three at once: the buffer, the inlined `text`/base64 `blob` copy inside the
//! response value, and `serde_json`'s serialized copy of that response. So they
//! are charged for all three ([`ReadResidency::InlinedInJsonResponse`]).
//! Charging them one object's worth would have made
//! `max_total_gateway_buffer_bytes` a number the gateway exceeded by ~3.7x on
//! its own documented surfaces.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

/// Accounting granularity. Permits are `u32`-counted by tokio, so charging one
/// permit per byte would overflow for any realistic budget; one permit per 4
/// KiB page keeps a 16 TiB budget representable while making every charge round
/// **up** (never under-charge). At the 10 MiB default per-operation bound a
/// single read costs 2560 permits.
pub(crate) const ADMISSION_UNIT_BYTES: u64 = 4096;

/// How many concurrent full-size buffering reads an *unconfigured* deployment
/// gets: `max_gateway_buffer_bytes x this`.
///
/// The dangerous default this deliberately avoids is "unset means zero means
/// admit nothing" -- an operator who never heard of this knob must not wake up
/// to a gateway that refuses every read. 32 x 10 MiB = 320 MiB is far above any
/// concurrency a 10 MiB-per-read workload reaches on a box that has not already
/// fallen over, so an unconfigured deployment behaves as it did before issue
/// #529 in every realistic case -- but is now bounded instead of unbounded.
pub(crate) const DEFAULT_CONCURRENT_BUFFERED_READS: u64 = 32;

/// Default bounded wait before shedding, in milliseconds. Long enough to ride
/// out the sub-second overlap of a burst, short enough that a shed is a fast,
/// honest answer rather than a timeout the caller experiences as an outage.
pub(crate) const DEFAULT_ADMISSION_WAIT_MS: u64 = 250;

/// The aggregate in-flight-byte budget for buffering, bucket-backed reads.
///
/// `permits: None` is the explicitly-disabled state (`0` in config): admission
/// always succeeds, which is exactly the pre-#529 behavior. It is reachable
/// only by an operator writing `max_total_gateway_buffer_bytes = 0`, never by
/// leaving the knob unset.
pub(crate) struct GatewayBufferBudget {
    permits: Option<Arc<Semaphore>>,
    /// The enforced ceiling in bytes, after the `>= per-read ceiling` raise.
    /// `0` when disabled.
    budget_bytes: u64,
    /// [`Self::budget_bytes`] in permits; a charge is clamped to this so a
    /// single read can never be permanently inadmissible.
    budget_units: u32,
    wait: Duration,
    /// Readers currently queued on the semaphore. The no-wait fast path is
    /// skipped while this is non-zero; see the FIFO paragraph in the module
    /// doc. It is an ordering hint, not accounting -- a stale read only costs
    /// one arrival a trip through the (still bounded) wait.
    waiting: AtomicUsize,
}

/// How much memory a read of `n` object bytes actually leaves resident, which
/// is what it is charged. The two shapes exist because they differ by ~3.7x and
/// the aggregate ceiling is meant to be a number, not an underestimate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReadResidency {
    /// The bytes leave the gateway as they arrived: the registry pull, the
    /// static-site serve, and the presigned commit's buffered leg write the
    /// buffer itself. One copy.
    BufferOnly,
    /// The bytes are additionally inlined into a JSON response value (the
    /// `fetch_asset` tool and MCP `resources/read`): the buffer, a `text` or
    /// base64 `blob` copy of it inside the response, and `serde_json`'s
    /// serialized copy of that response are all resident at the same time.
    InlinedInJsonResponse,
}

/// Standard padded base64 expansion: 4 output bytes per 3 input bytes, rounded
/// up. Used as the worst case for an inlined copy, since a body that is not
/// valid UTF-8 (or not a textual mime type) takes the `blob` branch.
fn base64_encoded_len(bytes: u64) -> u64 {
    bytes.div_ceil(3).saturating_mul(4)
}

impl ReadResidency {
    /// The bytes to charge for a read of `object_bytes`.
    ///
    /// The inlined case is deliberately the SUM rather than the max of the
    /// three residents: they overlap in time (the response value is serialized
    /// while it is still alive, and the base64 branch encodes from a buffer it
    /// has not dropped), and an aggregate memory ceiling that is occasionally
    /// optimistic is not a ceiling.
    ///
    /// Known residual, stated rather than hidden: a `text` body dense in
    /// control characters escapes to more than its base64 size inside
    /// `serde_json` (a NUL becomes six bytes). Assets like that are not a
    /// realistic shape for this surface, and the alternative -- charging 6x for
    /// every textual read -- would shed ordinary traffic to price in a body
    /// nobody publishes.
    pub(crate) fn residency_bytes(self, object_bytes: u64) -> u64 {
        match self {
            Self::BufferOnly => object_bytes,
            Self::InlinedInJsonResponse => {
                object_bytes.saturating_add(base64_encoded_len(object_bytes).saturating_mul(2))
            }
        }
    }
}

/// Proof that the bytes it accompanies were admitted against the budget.
/// Dropping it returns the charge.
pub(crate) struct BufferPermit(Option<OwnedSemaphorePermit>);

impl BufferPermit {
    /// A permit for bytes that never came from the bucket (inline registry
    /// content) or for a disabled budget. Charges nothing.
    pub(crate) fn unbudgeted() -> Self {
        Self(None)
    }
}

/// A [`BufferPermit`] parked on a response VALUE, for the surfaces that do not
/// write the object's bytes themselves.
///
/// The registry pull and the static-site serve own their response write, so
/// they can hold a plain `BufferPermit` in a local across it. The `fetch_asset`
/// tool and MCP `resources/read` cannot: they build a JSON value containing an
/// inlined copy of the object and hand it back to a caller that serializes and
/// writes it later. The charge has to travel with that value, or the ceiling
/// stops covering the two surfaces the runbook names alongside the other two.
///
/// `Arc` because the response types carrying this derive `Clone` (a guardrail
/// rewrite in the tool chokepoint rebuilds the response with `..response`), and
/// a cloned response must extend the charge rather than fail to compile or
/// silently drop it. `PartialEq` is deliberately vacuous: this field is
/// accounting attached to a response, never part of its identity.
#[derive(Clone, Default)]
pub(crate) struct ResponseBufferBudget(Option<Arc<BufferPermit>>);

impl ResponseBufferBudget {
    /// For responses that carry no admitted asset bytes at all -- every
    /// response in the gateway except an asset inlined into JSON.
    pub(crate) fn none() -> Self {
        Self(None)
    }

    /// Whether this response is actually holding a charge. Instrumentation the
    /// tests assert through; a release build sees it as dead.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn is_charged(&self) -> bool {
        matches!(&self.0, Some(permit) if permit.0.is_some())
    }
}

impl From<BufferPermit> for ResponseBufferBudget {
    fn from(permit: BufferPermit) -> Self {
        Self(Some(Arc::new(permit)))
    }
}

/// Never prints the object, only whether a charge is parked here.
impl std::fmt::Debug for ResponseBufferBudget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResponseBufferBudget")
            .field("charged", &self.is_charged())
            .finish()
    }
}

impl PartialEq for ResponseBufferBudget {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for ResponseBufferBudget {}

/// An object buffered in gateway memory, carrying the admission permit that
/// authorized it. The permit is released when this value is dropped, so the
/// budget tracks bytes that are actually resident.
pub(crate) struct BufferedObject {
    bytes: Vec<u8>,
    permit: BufferPermit,
}

impl BufferedObject {
    pub(crate) fn new(bytes: Vec<u8>, permit: BufferPermit) -> Self {
        Self { bytes, permit }
    }

    /// Bytes that were never charged: inline `stored_assets.content`, which is
    /// resident because the registry row is, not because a bucket read chose to
    /// hold it.
    pub(crate) fn unbudgeted(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            permit: BufferPermit::unbudgeted(),
        }
    }

    /// Splits the bytes from the permit. Callers MUST keep the returned permit
    /// alive for as long as they hold the bytes -- bind it to a `_budget` local
    /// in the scope that owns the buffer, never to `_`. That distinction is the
    /// whole aggregate-residency guarantee on the two surfaces that write their
    /// own response, so it is enforced by
    /// `asset_bucket`'s `the_admission_permit_is_never_discarded_at_a_split`
    /// scan rather than by this comment.
    pub(crate) fn into_parts(self) -> (Vec<u8>, BufferPermit) {
        (self.bytes, self.permit)
    }

    /// Like [`Self::into_parts`], but hands the charge back in the form the
    /// JSON-inlining surfaces need: something they can park on the response
    /// value that outlives them.
    pub(crate) fn into_response_parts(self) -> (Vec<u8>, ResponseBufferBudget) {
        (self.bytes, self.permit.into())
    }
}

impl std::ops::Deref for BufferedObject {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl AsRef<[u8]> for BufferedObject {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Prints the shape, never the bytes: this type wraps asset content, and a
/// `{:?}` in a log or an assertion message must not dump a tenant's object.
impl std::fmt::Debug for BufferedObject {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BufferedObject")
            .field("len", &self.bytes.len())
            .field("charged", &self.permit.0.is_some())
            .finish()
    }
}

/// A read the gateway refused to start because its aggregate buffering budget
/// was committed and stayed committed for the whole bounded wait.
pub(crate) struct AdmissionRefusal {
    pub(crate) requested_bytes: u64,
    pub(crate) budget_bytes: u64,
    pub(crate) waited_ms: u64,
}

impl GatewayBufferBudget {
    /// `budget_bytes` is the aggregate ceiling; `per_read_ceiling_bytes` is
    /// `max_gateway_buffer_bytes`. A budget below the per-read ceiling is
    /// raised to it: a configuration in which no single admissible read can
    /// ever be admitted is a deadlock dressed as a limit.
    pub(crate) fn new(budget_bytes: u64, per_read_ceiling_bytes: u64, wait: Duration) -> Self {
        if budget_bytes == 0 {
            return Self {
                permits: None,
                budget_bytes: 0,
                budget_units: 0,
                wait,
                waiting: AtomicUsize::new(0),
            };
        }
        let effective = budget_bytes.max(per_read_ceiling_bytes);
        let units = effective.div_ceil(ADMISSION_UNIT_BYTES).max(1);
        let budget_units = u32::try_from(units).unwrap_or(u32::MAX);
        Self {
            permits: Some(Arc::new(Semaphore::new(budget_units as usize))),
            budget_bytes: effective,
            budget_units,
            wait,
            waiting: AtomicUsize::new(0),
        }
    }

    /// The shared "no admission control" budget, for call sites that have no
    /// configuration to read (unit tests, and the explicitly-disabled state).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn disabled() -> &'static Self {
        static DISABLED: OnceLock<GatewayBufferBudget> = OnceLock::new();
        DISABLED.get_or_init(|| Self::new(0, 0, Duration::ZERO))
    }

    /// The enforced ceiling in bytes; `0` means admission control is disabled.
    ///
    /// This and the two accessors below are instrumentation the tests assert
    /// through (the refusal path carries its own copies of these numbers), so a
    /// release build sees them as dead. They stay in production source, next to
    /// the state they report on, rather than behind `#[cfg(test)]`.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn budget_bytes(&self) -> u64 {
        self.budget_bytes
    }

    /// Whether this budget actually refuses anything.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn is_enforced(&self) -> bool {
        self.permits.is_some()
    }

    /// Bytes currently uncommitted, rounded to the accounting unit. It is what
    /// lets a test assert that a code path (the streaming commit) consumed
    /// nothing.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn available_bytes(&self) -> u64 {
        match &self.permits {
            Some(permits) => permits.available_permits() as u64 * ADMISSION_UNIT_BYTES,
            None => u64::MAX,
        }
    }

    /// Charges a read of `bytes` object bytes against the budget, waiting at
    /// most the configured interval for capacity.
    ///
    /// What is charged is `residency.residency_bytes(bytes)` -- what the read
    /// will actually hold -- while the refusal reports `bytes`, the size of the
    /// object the caller asked for, because that is the number the caller and
    /// the operator can act on.
    ///
    /// Returns the permit to hold alongside the buffer, or an
    /// [`AdmissionRefusal`] the caller maps to a typed 503. The wait is bounded
    /// by construction: `timeout` cannot become an unbounded queue, and a
    /// closed semaphore (unreachable -- nothing closes it) fails **open**
    /// rather than turning a bookkeeping bug into a total read outage.
    pub(crate) async fn admit(
        &self,
        residency: ReadResidency,
        bytes: u64,
    ) -> Result<BufferPermit, AdmissionRefusal> {
        let Some(permits) = self.permits.clone() else {
            return Ok(BufferPermit::unbudgeted());
        };
        let charge = self.charge_units(residency.residency_bytes(bytes));
        // The fast path is skipped while anyone is queued. `try_acquire_many_owned`
        // never consults tokio's wait queue, so taking it unconditionally lets
        // an arriving small read barge past a large read already waiting --
        // which is the documented FIFO property inverted, not merely unproven.
        if self.waiting.load(Ordering::Acquire) == 0 {
            match Arc::clone(&permits).try_acquire_many_owned(charge) {
                Ok(permit) => return Ok(BufferPermit(Some(permit))),
                Err(TryAcquireError::NoPermits) => {}
                Err(TryAcquireError::Closed) => return Ok(BufferPermit::unbudgeted()),
            }
        }
        let started = Instant::now();
        self.waiting.fetch_add(1, Ordering::AcqRel);
        let outcome = tokio::time::timeout(self.wait, permits.acquire_many_owned(charge)).await;
        self.waiting.fetch_sub(1, Ordering::AcqRel);
        match outcome {
            Ok(Ok(permit)) => Ok(BufferPermit(Some(permit))),
            Ok(Err(_closed)) => Ok(BufferPermit::unbudgeted()),
            Err(_elapsed) => Err(AdmissionRefusal {
                requested_bytes: bytes,
                budget_bytes: self.budget_bytes,
                waited_ms: started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
            }),
        }
    }

    /// The permit cost of `bytes`: rounded UP to the accounting unit (never
    /// under-charge), at least one unit (a zero-byte read still occupies a
    /// slot), and never more than the whole budget (a charge larger than the
    /// budget could never be satisfied, so it would always burn the full wait
    /// before shedding instead of running when the gateway is idle).
    fn charge_units(&self, bytes: u64) -> u32 {
        let units = bytes.div_ceil(ADMISSION_UNIT_BYTES).max(1);
        u32::try_from(units)
            .unwrap_or(u32::MAX)
            .min(self.budget_units)
    }
}

#[cfg(test)]
#[path = "asset_admission_test.rs"]
mod asset_admission_test;
