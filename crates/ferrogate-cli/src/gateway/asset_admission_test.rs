// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Coverage for the aggregate buffering budget (issue #529). The
// properties worth pinning here are the ones a plausible re-implementation
// gets wrong: an unset knob must not mean "admit nothing", the wait before a
// shed must be bounded, the charge must be what the read will actually hold
// (rounded up, and counting the copies an inlining surface makes) rather than
// a slot, a queued large read must not be barged by later small ones, and the
// permit must outlive the bucket read that took it -- otherwise the ceiling
// throttles arrivals without bounding residency.
//
// The chokepoint's own use of all this is pinned next to it, in
// `asset_bucket.rs`: these tests prove the primitive, those prove the primitive
// is actually taken and held by `read_object_bounded`.

use std::time::{Duration, Instant};

use super::*;

const MIB: u64 = 1024 * 1024;

fn budget(total_bytes: u64, per_read_bytes: u64, wait_ms: u64) -> GatewayBufferBudget {
    GatewayBufferBudget::new(total_bytes, per_read_bytes, Duration::from_millis(wait_ms))
}

fn state_with(
    max_gateway_buffer_bytes: Option<u64>,
    max_total_gateway_buffer_bytes: Option<u64>,
    buffer_admission_wait_ms: Option<u64>,
) -> crate::state::AppState {
    crate::state::AppState::new(crate::config::Config {
        asset_bucket: crate::config::AssetBucketConfig {
            max_gateway_buffer_bytes,
            max_total_gateway_buffer_bytes,
            buffer_admission_wait_ms,
            ..crate::config::AssetBucketConfig::default()
        },
        ..crate::config::Config::default()
    })
}

/// THE dangerous default. An operator who has never heard of this knob must
/// not get a gateway that refuses reads, so "unset" resolves to a generous
/// multiple of the per-operation bound -- bounded, but far above any
/// concurrency a healthy box reaches.
#[test]
fn an_unset_ceiling_resolves_to_a_generous_bound_not_a_closed_door() {
    let state = state_with(None, None, None);

    assert_eq!(
        state.asset_total_gateway_buffer_bytes(),
        DEFAULT_CONCURRENT_BUFFERED_READS * 10 * MIB,
        "unset must resolve to {DEFAULT_CONCURRENT_BUFFERED_READS} x the per-operation bound"
    );
    assert_eq!(
        state.asset_buffer_admission_wait(),
        Duration::from_millis(DEFAULT_ADMISSION_WAIT_MS)
    );
}

/// The same default, exercised rather than asserted: the resolved budget
/// admits a full complement of full-size reads at once. A regression that
/// resolved "unset" to `0` permits -- the shape of this bug class -- fails
/// here on the first read, not in production.
#[tokio::test]
async fn an_unconfigured_deployment_admits_a_full_complement_of_full_size_reads() {
    let state = state_with(None, None, None);
    let budget = budget(
        state.asset_total_gateway_buffer_bytes(),
        state.asset_max_gateway_buffer_bytes(),
        0,
    );

    let mut held = Vec::new();
    for read in 0..DEFAULT_CONCURRENT_BUFFERED_READS {
        let permit = budget
            .admit(ReadResidency::BufferOnly, 10 * MIB)
            .await
            .unwrap_or_else(|_| panic!("read {read} of an unconfigured deployment was shed"));
        held.push(permit);
    }
    assert_eq!(budget.available_bytes(), 0, "the budget is now committed");
}

/// `0` is the operator's explicit opt-out: no admission control at all, the
/// literal pre-#529 behavior. It must never be confused with "admit nothing".
#[tokio::test]
async fn a_zero_ceiling_disables_admission_control_rather_than_admitting_nothing() {
    let budget = budget(0, 10 * MIB, 0);

    assert!(!budget.is_enforced());
    assert_eq!(budget.budget_bytes(), 0);
    let mut held = Vec::new();
    for _ in 0..1_000 {
        held.push(
            budget
                .admit(ReadResidency::BufferOnly, 10 * MIB)
                .await
                .map_err(|_| ())
                .expect("a disabled budget never sheds"),
        );
    }
}

/// A budget under the per-operation bound would make every full-size read
/// permanently inadmissible -- a deadlock wearing a limit's clothes. It is
/// raised instead.
#[tokio::test]
async fn a_budget_below_the_per_read_ceiling_is_raised_to_it() {
    let budget = budget(1024, 10 * MIB, 0);

    assert_eq!(budget.budget_bytes(), 10 * MIB);
    let _permit = budget
        .admit(ReadResidency::BufferOnly, 10 * MIB)
        .await
        .map_err(|_| ())
        .expect("one full-size read must always fit the budget");
}

/// The shed is a *bounded* wait followed by a typed refusal -- not an
/// indefinite queue, and not a truncated read. The elapsed-time assertion is
/// what distinguishes the two: a silent unbounded wait would never return.
#[tokio::test]
async fn an_over_budget_read_is_shed_after_the_bounded_wait_not_queued_forever() {
    let budget = budget(8 * MIB, 8 * MIB, 60);
    let _committed = budget
        .admit(ReadResidency::BufferOnly, 8 * MIB)
        .await
        .map_err(|_| ())
        .expect("the first read fits");

    let started = Instant::now();
    let refusal = budget
        .admit(ReadResidency::BufferOnly, 8 * MIB)
        .await
        .err()
        .expect("the second read must be shed, not admitted and not hung");
    let elapsed = started.elapsed();

    assert_eq!(refusal.requested_bytes, 8 * MIB);
    assert_eq!(refusal.budget_bytes, 8 * MIB);
    assert!(
        elapsed >= Duration::from_millis(50),
        "the read must WAIT for capacity before shedding (a burst absorber), \
         but it returned after {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "the wait must be bounded; it took {elapsed:?}"
    );
}

/// A shed is transient by construction: the capacity comes back when the
/// bytes do. Pinning this is what makes "retry" honest advice in the refusal
/// message.
#[tokio::test]
async fn releasing_a_permit_returns_its_charge_to_the_budget() {
    let budget = budget(8 * MIB, 8 * MIB, 0);
    let permit = budget
        .admit(ReadResidency::BufferOnly, 8 * MIB)
        .await
        .map_err(|_| ())
        .expect("the first read fits");
    assert_eq!(budget.available_bytes(), 0);
    assert!(budget
        .admit(ReadResidency::BufferOnly, 8 * MIB)
        .await
        .is_err());

    drop(permit);

    assert_eq!(budget.available_bytes(), 8 * MIB);
    let _second = budget
        .admit(ReadResidency::BufferOnly, 8 * MIB)
        .await
        .map_err(|_| ())
        .expect("the retry the refusal message promises must actually work");
}

/// Why this is a BYTE budget and not a request-count semaphore: a static site
/// serving 4 KiB files is charged 4 KiB apiece. A count-based cap sized for
/// full-size reads would have shed all but a handful of these while using
/// under 1% of the memory it was protecting.
#[tokio::test]
async fn small_reads_are_charged_their_size_not_a_full_slot() {
    let budget = budget(8 * MIB, 8 * MIB, 0);

    let mut held = Vec::new();
    for read in 0..512 {
        held.push(
            budget
                .admit(ReadResidency::BufferOnly, 4096)
                .await
                .map_err(|_| ())
                .unwrap_or_else(|()| panic!("small read {read} was shed by a byte budget")),
        );
    }
    assert_eq!(
        budget.available_bytes(),
        6 * MIB,
        "512 x 4 KiB is 2 MiB of an 8 MiB budget"
    );
}

/// The property that separates a memory ceiling from a rate limiter: the
/// permit is bound to the BYTES, not to the bucket read. If it were released
/// when the read returned, N requests could pass admission one after another
/// and then hold N buffers concurrently through hashing, base64 encoding and
/// the response write -- the exact aggregate #529 exists to bound.
#[tokio::test]
async fn the_charge_is_held_until_the_buffered_bytes_are_dropped() {
    let budget = budget(8 * MIB, 8 * MIB, 0);
    let permit = budget
        .admit(ReadResidency::BufferOnly, 4 * MIB)
        .await
        .map_err(|_| ())
        .expect("half the budget fits");
    let object = BufferedObject::new(vec![0_u8; 4 * MIB as usize], permit);

    assert_eq!(budget.available_bytes(), 4 * MIB);
    // Splitting the object apart must NOT release the charge -- the response
    // path does exactly this before writing the body.
    let (bytes, held) = object.into_parts();
    assert_eq!(bytes.len(), 4 * MIB as usize);
    assert_eq!(budget.available_bytes(), 4 * MIB);

    drop(held);
    assert_eq!(budget.available_bytes(), 8 * MIB);
}

/// Review finding 3 on the first round: every size the suite used (4096,
/// 64 KiB, 4 MiB, 8 MiB, 10 MiB) was an exact multiple of the accounting unit,
/// so `div_ceil` -> `/` -- an under-charge on every partial page -- survived
/// the whole suite. One unaligned size pins the direction of the rounding.
#[tokio::test]
async fn a_charge_rounds_up_to_the_accounting_unit_never_down() {
    let budget = budget(8 * MIB, 8 * MIB, 0);

    let _permit = budget
        .admit(ReadResidency::BufferOnly, ADMISSION_UNIT_BYTES + 1)
        .await
        .map_err(|_| ())
        .expect("one byte over a page still fits an 8 MiB budget");

    assert_eq!(
        budget.available_bytes(),
        8 * MIB - 2 * ADMISSION_UNIT_BYTES,
        "{} bytes must be charged TWO {ADMISSION_UNIT_BYTES}-byte units, not one: rounding down \
         lets a read hold a page the budget never accounted for",
        ADMISSION_UNIT_BYTES + 1
    );
}

/// A read that inlines the object into a JSON response holds up to three copies
/// of it at once (the buffer, the `text`/`blob` copy, `serde_json`'s serialized
/// copy), so it is charged for three. Charging it one -- what the first round
/// did -- made `max_total_gateway_buffer_bytes` a number the gateway's own
/// documented surfaces exceeded by ~3.7x.
#[tokio::test]
async fn an_inlined_read_is_charged_for_the_copies_it_will_hold() {
    let object = 3 * ADMISSION_UNIT_BYTES;

    assert_eq!(
        ReadResidency::BufferOnly.residency_bytes(object),
        object,
        "a read that writes its buffer out holds exactly one copy"
    );
    assert_eq!(
        ReadResidency::InlinedInJsonResponse.residency_bytes(object),
        object + 2 * (object / 3 * 4),
        "an inlined read holds the buffer plus two base64-sized copies"
    );

    // And it is the charge, not just an arithmetic helper: the same budget
    // admits three plain reads of this object and only one inlined one.
    let plain = budget(9 * ADMISSION_UNIT_BYTES, ADMISSION_UNIT_BYTES, 0);
    let mut held = Vec::new();
    for read in 0..3 {
        held.push(
            plain
                .admit(ReadResidency::BufferOnly, object)
                .await
                .map_err(|_| ())
                .unwrap_or_else(|()| panic!("plain read {read} of 3 must fit a 3x budget")),
        );
    }
    assert_eq!(
        plain.available_bytes(),
        0,
        "three plain reads of this object fill the budget exactly"
    );

    let inlined = budget(9 * ADMISSION_UNIT_BYTES, ADMISSION_UNIT_BYTES, 0);
    let _first = inlined
        .admit(ReadResidency::InlinedInJsonResponse, object)
        .await
        .map_err(|_| ())
        .expect("the first inlined read fits");
    assert!(
        inlined
            .admit(ReadResidency::InlinedInJsonResponse, object)
            .await
            .is_err(),
        "a second inlined read must not fit a budget that holds exactly one of them"
    );
}

/// Review finding 4 on the first round: the module doc promised a large read at
/// the head of the queue could not be starved by a stream of small ones, and
/// `try_acquire_many_owned` -- which never consults tokio's wait queue --
/// delivered the opposite. Every arriving small read barged past the queued
/// large one, which then burned its whole wait and shed.
///
/// The fixture is deterministic rather than statistical: a larger read is
/// already queued for the capacity, so the small read may only proceed once
/// that read has left the queue.
///
/// WHAT THIS TEST DOES AND DOES NOT PROVE (#544). It proves the observable
/// property -- a small read arriving behind a queued large one does not
/// complete immediately. It does NOT prove that the `waiting` counter guard in
/// `admit` is what delivers that, because tokio's partial reservation drains
/// the semaphore to 0 as soon as the large read queues, so
/// `try_acquire_many_owned` on the fast path would fail anyway. Whether that
/// guard is load-bearing or redundant is an open question this fixture cannot
/// answer; see the mutation note on #544.
///
/// The assertion is on ELAPSED TIME rather than on a refusal, because tokio
/// hands the freed capacity to the next waiter as soon as the large read gives
/// up: the small read is allowed to succeed, just not to succeed *immediately*.
/// Barging returns in microseconds; queueing cannot return before the large
/// read's own bounded wait expires.
#[tokio::test]
async fn a_queued_large_read_is_not_barged_by_a_later_small_one() {
    const WAIT_MS: u64 = 400;
    let budget = std::sync::Arc::new(budget(8 * MIB, 8 * MIB, WAIT_MS));
    let _half = budget
        .admit(ReadResidency::BufferOnly, 4 * MIB)
        .await
        .map_err(|_| ())
        .expect("the first half of the budget is free");

    let queued = tokio::spawn({
        let budget = std::sync::Arc::clone(&budget);
        async move {
            budget
                .admit(ReadResidency::BufferOnly, 8 * MIB)
                .await
                .is_ok()
        }
    });
    // Let the large read reach the wait queue.
    tokio::time::sleep(Duration::from_millis(30)).await;
    // #544: the original precondition here asserted that half the budget was
    // still FREE while the large read waited. That can never be true, and the
    // test therefore failed deterministically the moment it landed.
    //
    // tokio's batch semaphore reserves PARTIALLY. At `poll_acquire`, when the
    // available permits are fewer than needed, it takes all of them and queues
    // for the remainder (`batch_semaphore.rs`: `remaining = (needed -
    // acquired) - curr; (0, ...)` -- the semaphore is set to 0), and
    // `add_permits_locked` keeps assigning released permits to the waiter at
    // the head of the queue. So the queued 8 MiB read DRAINS the free 4 MiB
    // into its own reservation and `available_bytes()` is 0.
    //
    // That is the anti-barging property itself, provided by tokio rather than
    // by us: capacity a queued read is waiting for stops being available to
    // anyone else. The precondition that actually establishes the fixture is
    // therefore "the large read is still queued", not "capacity is free".
    assert!(
        !queued.is_finished(),
        "the large read must still be queued -- if it already completed, the small read below \
         is racing nothing and the elapsed-time assertion proves nothing"
    );
    assert_eq!(
        budget.available_bytes(),
        0,
        "the queued read must have absorbed the free capacity into its reservation"
    );

    let started = Instant::now();
    let _small = budget.admit(ReadResidency::BufferOnly, 4096).await;
    let elapsed = started.elapsed();

    assert!(
        elapsed >= Duration::from_millis(WAIT_MS / 2),
        "a 4 KiB read arriving after an 8 MiB read queued took the 4 MiB sitting free after \
         {elapsed:?} -- it barged the queue instead of joining it, which is what starves the \
         large read under sustained small-read load"
    );
    assert!(
        !queued.await.expect("the queued read task"),
        "the fixture never frees capacity, so the large read is expected to shed -- if it \
         succeeded, the budget accounting changed and this test measures something else"
    );
}

/// Inline registry content is resident because the row is, not because a
/// bucket read chose to hold it, so it is not charged.
#[tokio::test]
async fn inline_content_is_not_charged_against_the_bucket_read_budget() {
    let budget = budget(8 * MIB, 8 * MIB, 0);
    let inline = BufferedObject::unbudgeted(b"inline bytes".to_vec());

    assert_eq!(&*inline, b"inline bytes");
    assert_eq!(budget.available_bytes(), 8 * MIB);
}
