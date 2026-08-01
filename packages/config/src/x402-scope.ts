/**
 * Port of the structural half of `ferrogate-config`'s `x402_scope.rs`
 * (inventory §5.2, x402 — deprioritized per the x402 directive): the
 * scope-chain vocabulary, id normalization, precedence order, and the
 * duplicate/empty-scope load-time checks.
 *
 * PORT-TODO(inventory §5.2): the TYPED policy model (`X402SpendPolicy` +
 * `validate()` + `X402PolicyConfigError`) and the full
 * `resolve_effective_x402_spend_policy` inheritance resolution live in
 * `@ferrogate/policy` (wave 2, and x402 is deprioritized). The
 * policy-invariant `Invalid` branch of `validate_scoped_x402_spend_policies`
 * delegates to that crate; only the scope-shape checks (empty / duplicate) are
 * ported here. Each declared policy is carried as an opaque value until the
 * policy crate lands.
 *
 * PORT-TODO(inventory §5.2) — THE STATED BLOCKER ABOVE IS NOW STALE (parity
 * audit 2026-07-31, `docs/rewrite/parity-audit-policy-core.md`).
 *
 * `@ferrogate/policy` HAS landed the typed model: `packages/policy/src/x402/config.ts`
 * exports `X402SpendPolicy`, `ValidatedX402SpendPolicy`, `validateX402SpendPolicy`
 * and `X402PolicyConfigError` (459 lines, exercised by `packages/policy/test/x402.test.ts`,
 * 476 lines). So the per-policy `validate()` leg is no longer blocked on a
 * missing owner — it is simply unwired, and `x402_spend_policies` is still typed
 * `z.array(z.unknown())` in `schema/config.ts`. Net effect: an operator's x402
 * spend policy is checked only for a non-blank, non-duplicate
 * `(scope_type, scope_id)`; every money-shaped invariant Rust enforces at LOAD
 * (`load_x402_spend_policy_toml` → `X402SpendPolicyConfig::validate`) is skipped,
 * which is the opposite of #351's "money config fails at load, never at the
 * first payment".
 *
 * TWO legs remain genuinely UNPORTED anywhere in the workspace (verified by
 * `grep -rn "EffectiveX402\|X402ScopeChain\|load_x402_spend_policy_toml" packages apps`):
 *   - `X402ScopeChain`, `X402PolicyScopeRef`, `EffectiveX402SpendPolicy` and
 *     `resolve_effective_x402_spend_policy` (the broadest→narrowest inheritance
 *     resolution over the 5 scope kinds declared above);
 *   - `X402SpendPolicyConfig` / `load_x402_spend_policy_toml` /
 *     `default_x402_spend_policy` from `crates/ferrogate-config/src/x402.rs`.
 *
 * Priority: LOW — x402/Solana is deprioritized by owner directive, so this is
 * recorded rather than scheduled. Fix the RATIONALE even if the code waits: the
 * `test.todo("delegate X402SpendPolicy.validate() to @ferrogate/policy once
 * ported")` in `test/port-todo.test.ts` now describes a dependency that exists.
 */
import { z } from "zod";

/**
 * One level of the tenancy chain an x402 spend policy may be declared at,
 * ordered broadest → narrowest (the precedence rank).
 */
export const x402PolicyScopeKindSchema = z.enum(["tenant", "project", "workspace", "key", "run"]);
export type X402PolicyScopeKind = z.infer<typeof x402PolicyScopeKindSchema>;

/** Every scope kind, broadest first — the canonical inheritance order. */
export const X402_POLICY_SCOPE_KINDS: X402PolicyScopeKind[] = [
  "tenant",
  "project",
  "workspace",
  "key",
  "run",
];

/** A scoped x402 spend-policy declaration (policy body opaque; see PORT-TODO). */
export interface X402ScopedSpendPolicy {
  scope_type: X402PolicyScopeKind;
  scope_id: string;
  policy: unknown;
}

/** `normalize_x402_scope_id`: the SAME normalization resolution uses (trim). */
export function normalizeX402ScopeId(scopeId: string): string {
  return scopeId.trim();
}

/** Typed reasons a scoped-policy set is rejected at load. */
export type X402ScopedPolicyError =
  | { type: "duplicate_scope"; scope_type: X402PolicyScopeKind; scope_id: string }
  | { type: "empty_scope_id"; scope_type: X402PolicyScopeKind };

/**
 * `impl Display for X402ScopedPolicyError`, VERBATIM.
 *
 * These two strings are what `validate_x402_spend_policies` splices into `field
 * x402_spend_policies: ...`, so they are operator-facing error identity, not
 * prose — an operator grepping runbooks or a support ticket for the Rust text
 * has to find it. They had been paraphrased ("two x402 spend policies target the
 * same scope project \"p1\"" for "duplicate x402 spend policy for project p1"),
 * which reads fine and matches nothing.
 *
 * Rust's third variant, `Invalid { .. , error: X402PolicyConfigError }`, is
 * absent on purpose and is the subject of the module PORT-TODO: it delegates to
 * the policy crate's own structural validation, which x402 being deprioritized
 * leaves unported. It is NOT re-worded here, because inventing its text would
 * make a marker look closed.
 */
export function describeX402ScopedPolicyError(error: X402ScopedPolicyError): string {
  switch (error.type) {
    case "duplicate_scope":
      return `duplicate x402 spend policy for ${error.scope_type} ${error.scope_id}`;
    case "empty_scope_id":
      return `x402 spend policy at scope ${error.scope_type} has an empty scope_id`;
  }
}

/**
 * `validate_scoped_x402_spend_policies` (scope-shape half): no two declarations
 * may target the same `(scope_type, scope_id)` and no `scope_id` may be blank.
 * The empty default (no declarations) always passes — every scope then resolves
 * to the disabled deny-all policy.
 */
export function validateScopedX402SpendPolicies(
  declared: X402ScopedSpendPolicy[],
): X402ScopedPolicyError | null {
  const seen = new Set<string>();
  for (const entry of declared) {
    const scopeId = normalizeX402ScopeId(entry.scope_id);
    if (scopeId.length === 0) {
      return { type: "empty_scope_id", scope_type: entry.scope_type };
    }
    const key = `${entry.scope_type}\u0000${scopeId}`;
    if (seen.has(key)) {
      return { type: "duplicate_scope", scope_type: entry.scope_type, scope_id: scopeId };
    }
    seen.add(key);
    // PORT-TODO(inventory §5.2): delegate the policy-invariant check to
    // `@ferrogate/policy`'s `X402SpendPolicy.validate()` once ported.
  }
  return null;
}
