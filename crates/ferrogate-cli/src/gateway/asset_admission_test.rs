// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Coverage for the aggregate buffering budget (issue #529). The
// properties worth pinning here are the ones a plausible re-implementation
// gets wrong: an unset knob must not mean "admit nothing", the wait before a
// shed must be bounded, the charge must be the declared size rather than a
// slot, and the permit must outlive the bucket read that took it -- otherwise
// the ceiling throttles arrivals without bounding residency.

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
            .admit(10 * MIB)
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
                .admit(10 * MIB)
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
        .admit(10 * MIB)
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
        .admit(8 * MIB)
        .await
        .map_err(|_| ())
        .expect("the first read fits");

    let started = Instant::now();
    let refusal = budget
        .admit(8 * MIB)
        .await
        .map_err(|refusal| refusal)
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
        .admit(8 * MIB)
        .await
        .map_err(|_| ())
        .expect("the first read fits");
    assert_eq!(budget.available_bytes(), 0);
    assert!(budget.admit(8 * MIB).await.is_err());

    drop(permit);

    assert_eq!(budget.available_bytes(), 8 * MIB);
    let _second = budget
        .admit(8 * MIB)
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
                .admit(4096)
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
        .admit(4 * MIB)
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

/// Inline registry content is resident because the row is, not because a
/// bucket read chose to hold it, so it is not charged.
#[tokio::test]
async fn inline_content_is_not_charged_against_the_bucket_read_budget() {
    let budget = budget(8 * MIB, 8 * MIB, 0);
    let inline = BufferedObject::unbudgeted(b"inline bytes".to_vec());

    assert_eq!(&*inline, b"inline bytes");
    assert_eq!(budget.available_bytes(), 8 * MIB);
}
