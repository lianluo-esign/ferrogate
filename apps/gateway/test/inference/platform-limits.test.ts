/**
 * PINS FOR THE PLATFORM LIMITS in `src/inference/` — the behaviors Cloudflare
 * Workers genuinely cannot reproduce, asserted in the APPROXIMATED form the
 * port ships.
 *
 * Same contract as `test/streaming/parity-limits.test.ts`, for the other kind
 * of kept PORT-TODO. A platform-limit marker without a test is the worst of
 * both worlds: the Rust behavior is gone AND nothing holds the substitute, so
 * the substitute can silently rot into something weaker than what the comment
 * promises. Each marker that stays open must therefore leave a failing test
 * behind if its approximation is broken.
 *
 * ## What is pinned WHERE
 *
 *  - `RequestIdFactory` (`src/inference/ports.ts`) — HERE. Rust formats a
 *    process-wide `AtomicU64` as `fg-{:016x}`, so ids are ordered by
 *    comparison. A Worker has no shared mutable process state across isolates
 *    and the only durable counter is a Durable Object, i.e. a network hop per
 *    request to mint a log id. The approximation is the same SHAPE from
 *    `crypto.getRandomValues`.
 *  - `providerTransportFailureClass` (`src/inference/dispatch.ts`) — pinned by
 *    `test/inference/dispatch.test.ts`, which asserts the three classes workerd
 *    CAN discriminate (`timeout`, `request`, `connect`) in the exact Rust
 *    message form (`provider request failed (timeout)`).
 *  - the `chars/4` token estimate (`src/inference/estimate.ts`) — pinned by
 *    `test/inference/estimate.test.ts` ("the chars/4 approximation fails CLOSED
 *    against the BPE leg"), which holds the DIRECTION of the error, so a future
 *    tokenizer dependency cannot land in a direction that loosens the TPM gate.
 */
import { describe, expect, test } from "vitest";
import { defaultRequestIds } from "../../src/inference/index.js";

/** `fg-` + exactly 16 LOWERCASE hex digits — the Rust `fg-{:016x}` shape. */
const RUST_REQUEST_ID_SHAPE = /^fg-[0-9a-f]{16}$/;

describe("request ids keep the Rust SHAPE without the Rust ordering", () => {
  test("every id matches `fg-` + 16 lowercase hex digits", () => {
    for (let i = 0; i < 64; i += 1) {
      expect(defaultRequestIds.next()).toMatch(RUST_REQUEST_ID_SHAPE);
    }
  });

  test("ids are unique across a large draw", () => {
    // 2^-64 per pair rather than impossible-by-construction, which is the
    // documented cost of dropping the counter.
    const ids = new Set<string>();
    for (let i = 0; i < 512; i += 1) ids.add(defaultRequestIds.next());
    expect(ids.size).toBe(512);
  });

  test("the digits are RANDOM, not a counter formatted to look random", () => {
    // A `fg-{:016x}` counter starting near zero produces ids that all share a
    // long leading run of `0`s; a CSPRNG spreads the leading nibble across the
    // hex alphabet. 512 draws sharing one leading nibble has probability
    // 16^-511, so this cannot flake — but it DOES go red the moment the factory
    // is replaced by a sequence, which is the substitution this pin exists to
    // catch (a per-isolate counter would collide across isolates while looking
    // perfectly ordered in a single-isolate test).
    const leading = new Set<string>();
    for (let i = 0; i < 512; i += 1) leading.add(defaultRequestIds.next()[3] ?? "");
    expect(leading.size).toBeGreaterThan(1);
  });

  test("a fresh isolate's ids do not continue any previous sequence", () => {
    // The property Rust HAD and this port does not: two ids cannot be ordered.
    // Asserted only as "not adjacent", which is what a resumed counter would
    // produce, so the test states the loss without forbidding a future ordered
    // implementation from being introduced deliberately.
    const first = defaultRequestIds.next();
    const second = defaultRequestIds.next();
    const asInt = (id: string): bigint => BigInt(`0x${id.slice(3)}`);
    expect(asInt(second) - asInt(first)).not.toBe(1n);
  });
});
