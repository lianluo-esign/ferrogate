/**
 * The bucket function — the one piece of arithmetic the whole sample rests on.
 *
 * ## Why a HASH and not a random number
 *
 * `Math.random() < rate` samples the right FRACTION and answers no question. A
 * conversation's second turn would land on the other side of the sample from
 * its first, so "did this conversation get worse" is unanswerable; a replayed
 * request would be sampled differently, so nothing is reproducible; and a test
 * can only assert a distribution, never a decision.
 *
 * Hashing a stable key gives all three back: the same key is always in or
 * always out, at a given rate, in every isolate and on every replay.
 *
 * ## Why it is SALTED
 *
 * `inference/shadow.ts` already buckets on a sticky caller key, and other
 * hash-based decisions (canary splits) do too. Two unsalted hash samplers over
 * the same key are perfectly correlated: the 5% of traffic that is mirrored
 * would be exactly the 5% that is evaluated, so the "sample" would be a biased
 * sub-population presented as a random one — and nobody reading a dashboard
 * would ever see that. The salt makes this sampler's population independent of
 * every other one.
 *
 * The salt is VERSIONED. Changing it re-rolls which conversations are in the
 * sample, which resets comparability of any series that spans the change, so
 * changing it is a deliberate act with a visible name rather than a silent tweak.
 *
 * ## FNV-1a, 32-bit
 *
 * Chosen because it needs no crypto, no async and no allocation: this runs
 * synchronously on the request path before `next()`, where a `crypto.subtle`
 * digest (async, and therefore a `await` in front of the client's response) is
 * exactly what must not happen. FNV-1a's avalanche is more than adequate for
 * bucketing — this is not a security decision and no attacker gains anything by
 * landing in or out of a quality sample.
 */

/**
 * Versioned salt. See the module docs: it is what keeps this sampler's
 * population independent of the shadow/canary samplers over the same keys.
 */
export const ONLINE_EVAL_SAMPLING_SALT = "ferrogate.online_eval.v1:";

/**
 * FNV-1a over the UTF-16 code units of `value`, finished with a bit mixer, as
 * an unsigned 32-bit integer.
 *
 * ## Why the finalizer is not optional
 *
 * Plain FNV-1a avalanches poorly in its HIGH bits, and the high bits are
 * exactly the ones {@link sampleBucket} reads (it divides by 2^32). Measured on
 * this tree's own test corpus — 4000 sequential keys `req_0…req_3999`, the
 * shape a load generator and a real per-request id both produce — plain FNV-1a
 * put **14.25%** of keys under a 0.10 threshold. A sampler that claims 10% and
 * takes 14% of a structured key space is not a rounding error: every rate an
 * operator configures is wrong by an unknown factor that depends on what their
 * ids look like.
 *
 * The finalizer is `lowbias32` (Chris Wellons' searched constants), which is
 * the standard fix and is what brings the same corpus back to ~10%. It is
 * `Math.imul` throughout because `h * 0x7feb352d` exceeds 2^53 and would lose
 * precisely the low bits the mix exists to spread.
 */
export function fnv1a32(value: string): number {
  let hash = 0x811c9dc5;
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    hash = Math.imul(hash ^ (code & 0xff), 0x01000193);
    const high = (code >>> 8) & 0xff;
    if (high !== 0) hash = Math.imul(hash ^ high, 0x01000193);
  }
  hash ^= hash >>> 16;
  hash = Math.imul(hash, 0x7feb352d);
  hash ^= hash >>> 15;
  hash = Math.imul(hash, 0x846ca68b);
  hash ^= hash >>> 16;
  return hash >>> 0;
}

/**
 * `key` → a stable bucket in `[0, 1)`.
 *
 * `salt` is a parameter only so a test can prove the salt is applied at all;
 * production always takes the default.
 */
export function sampleBucket(key: string, salt: string = ONLINE_EVAL_SAMPLING_SALT): number {
  return fnv1a32(`${salt}${key}`) / 0x1_0000_0000;
}
