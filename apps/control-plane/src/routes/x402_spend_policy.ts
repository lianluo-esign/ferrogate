/**
 * Contract group `x402_spend_policy` (3 operations), all `admin.read`.
 *
 * ```
 *   GET  /admin/v1/x402-spend-policies
 *   GET  /admin/v1/x402-spend-policies/effective   the resolved policy for a scope
 *   POST /admin/v1/x402-spend-policies/evaluate    would this spend be allowed?
 * ```
 *
 * `evaluate` is a POST that is `admin.read`, and that is correct rather than a
 * contract typo: it takes a candidate spend in the body and answers whether the
 * policy WOULD allow it. It reserves nothing, holds nothing and settles
 * nothing — the same read-only-POST shape as the guardrail `dry-run`.
 *
 * Note `effective` and `evaluate` are STATIC segments competing with no
 * `{id}` route in this group, so `contract.ts`'s specificity ranking is not
 * even exercised here; they are matched literally.
 *
 * PORT-TODO(x402): the x402/Solana payment family is deprioritized per the
 * standing directive, so resolution and evaluation are implemented over the
 * stored policy rows only. The three routes exist, are guarded, and answer the
 * documented shapes; the settlement path lands with `@ferrogate/payments`.
 */
import { z } from "zod";
import {
  type GroupModule,
  crudGroup,
  json,
  readJson,
  readOnlyCollection,
  scopeOf,
} from "./resource.js";

const POLICIES = "x402-spend-policies";

export const x402EvaluateRequestSchema = z
  .object({
    amount: z.number().nonnegative(),
    currency: z.string().trim().min(1).default("USD"),
    tenant_id: z.string().trim().min(1).optional(),
    resource: z.string().trim().min(1).optional(),
  })
  .strict();

export const x402SpendPolicyRoutes: GroupModule = crudGroup(
  "x402_spend_policy",
  [readOnlyCollection(POLICIES, "x402_spend_policy")],
  {
    getEffectiveX402SpendPolicy: async (c) => {
      const deps = c.get("deps");
      const scope = scopeOf(c);
      const tenantId =
        new URL(c.req.url).searchParams.get("tenant_id") ??
        (scope.kind === "tenant" ? scope.tenantId : null);
      const record =
        tenantId === null ? null : await deps.store.get(POLICIES, scope, `tenant:${tenantId}`);
      return json(c, 200, {
        object: "x402_spend_policy",
        tenant_id: tenantId,
        // `null` means "no policy configured", which is NOT the same as an
        // unlimited policy — the caller must distinguish them.
        x402_spend_policy: record,
      });
    },

    evaluateX402SpendPolicy: async (c) => {
      const deps = c.get("deps");
      const scope = scopeOf(c);
      const request = await readJson(c, x402EvaluateRequestSchema);
      const tenantId = request.tenant_id ?? (scope.kind === "tenant" ? scope.tenantId : null);
      const policy =
        tenantId === null ? null : await deps.store.get(POLICIES, scope, `tenant:${tenantId}`);

      const cap = typeof policy?.max_amount === "number" ? policy.max_amount : null;
      // Fail closed on an unknown policy is wrong here (no policy = no x402
      // limit configured), but an amount over a configured cap is denied.
      const allowed = cap === null || request.amount <= cap;
      return json(c, 200, {
        object: "x402_spend_evaluation",
        allowed,
        amount: request.amount,
        currency: request.currency,
        tenant_id: tenantId,
        policy_id: policy?.id ?? null,
        max_amount: cap,
        reason: allowed ? null : "amount exceeds the configured x402 spend cap",
      });
    },
  },
);
