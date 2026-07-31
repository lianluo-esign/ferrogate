/**
 * The two primitives the worker-plane credential path needs, on WebCrypto.
 *
 * Ported from `crates/ferrogate-runtime/src/self_hosted_worker.rs`
 * (`constant_time_secret_eq`) and `crates/ferrogate-gateway/src/server/agent_jobs.rs`
 * (`agent_job_run_id`).
 */

/**
 * Constant-time string comparison (Rust `constant_time_secret_eq`, issue #114).
 *
 * `===` on a secret leaks where the first differing byte is, so a differing-
 * PREFIX attempt is distinguishable from a differing-SUFFIX one by response
 * timing and an attacker can walk the secret out byte by byte. This compares
 * every byte of both inputs unconditionally and folds the differences together.
 *
 * Length is folded into the accumulator rather than short-circuited on, so a
 * wrong-length guess costs the same as a right-length one.
 */
export function timingSafeEqualStrings(expected: string, presented: string): boolean {
  const a = new TextEncoder().encode(expected);
  const b = new TextEncoder().encode(presented);
  // Start with the length difference so an early `return false` is never
  // needed: a wrong-length guess can no longer be told apart from a
  // right-length one by how quickly the answer comes back.
  let difference = a.length ^ b.length;
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i += 1) {
    // Past-the-end reads are `undefined`; `?? 0` keeps every iteration uniform.
    difference |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return difference === 0;
}

/** Lowercase hex of a byte slice. */
function toHex(bytes: Uint8Array): string {
  let hex = "";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return hex;
}

/** `sha256` of a byte slice, lowercase hex. */
export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer,
  );
  return toHex(new Uint8Array(digest));
}

/**
 * Rust `agent_job_run_id(tenant_id, idempotency_key)`.
 *
 * The whole idempotency mechanism: submission does not mint a random id and
 * then look for a duplicate afterwards (which races), it ADDRESSES a
 * deterministic id, so a retry with the same key computes the same id by
 * construction. The tenant is mixed into the digest, so identical keys in
 * different tenants are different jobs and no key can be used to probe for (or
 * clobber) another tenant's run.
 *
 * `0x1f` (unit separator) is a domain break so `("ab", "c")` and `("a", "bc")`
 * cannot hash to the same job id. The id keeps the first 16 digest bytes,
 * exactly as Rust does.
 */
export async function agentJobRunId(tenantId: string, idempotencyKey: string): Promise<string> {
  const encoder = new TextEncoder();
  const tenant = encoder.encode(tenantId);
  const key = encoder.encode(idempotencyKey);
  const message = new Uint8Array(tenant.length + 1 + key.length);
  message.set(tenant, 0);
  message[tenant.length] = 0x1f;
  message.set(key, tenant.length + 1);
  const digest = await sha256Hex(message);
  return `job-${digest.slice(0, 32)}`;
}

/** Rust `canonical_target_sha256` shape: `sha256:<64 lowercase hex>`. */
export async function canonicalTargetFingerprint(canonicalTarget: string): Promise<string> {
  return `sha256:${await sha256Hex(new TextEncoder().encode(canonicalTarget))}`;
}
