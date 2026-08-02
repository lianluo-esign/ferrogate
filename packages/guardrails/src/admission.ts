/**
 * ADMISSION — "may this revision document become a policy the data plane will
 * be asked to enforce?"
 *
 * ## Why this is a package-level concern
 *
 * `apps/control-plane` mints guardrail policy revisions; `apps/gateway` compiles
 * and enforces them. The gateway compiles EAGERLY, once per isolate, at
 * construction (`apps/gateway/src/guardrails/binding.ts::policySourceFromStore`),
 * so a revision it cannot compile is not a per-request failure — it is a boot
 * failure. Wave 16 measured that and refused to project the control plane's
 * documents at all, because projecting a partial revision would have taken the
 * gateway's whole guardrail source down.
 *
 * The answer is to tighten ADMISSION, not to loosen compilation, and Rust does
 * exactly that: `create_guardrail_policy_revision`
 * (`crates/ferrogate-gateway/src/state.rs`) calls
 * `build_guardrail_policy_runtime(revision, ..)?` — it COMPILES the candidate —
 * before it inserts a row, and the handler renders the failure as `400`
 * `invalid_guardrail_policy` (`server/guardrail_policies.rs::write_guardrail_error`,
 * the `None =>` arm).
 *
 * ## What this does NOT re-implement
 *
 * Nothing. {@link admitPolicyRevision} runs {@link policyRevisionSchema} and
 * {@link validatePolicyRevision} — the SAME pair the data plane's
 * `InMemoryGuardrailPolicyStore.putRevision` and `D1GuardrailPolicyStore.putRevision`
 * run before a revision is allowed into the store, and whose detector leg
 * ({@link validateDetectorDefinition}) is what the gateway's `buildDetector`
 * runs on every check. A second validator here would be the drift this module
 * exists to prevent. The verdict is theirs; this module only adds the FIELD PATH
 * (see {@link locateRevisionField}, which never decides accept-or-refuse).
 *
 * ## What admission provably CANNOT cover
 *
 * `buildDetector` also resolves `secret_ref` / `fingerprint_secret_ref` against
 * the GATEWAY's Worker bindings. The control plane is a different Worker and
 * cannot see them, so "the ref is non-empty" is the strongest statement
 * available here — a ref that is bound nowhere is unreachable from admission by
 * construction. That residue is why `policySourceFromStore` also has to fail one
 * policy closed rather than fail the boot; the two halves are complementary, not
 * alternatives.
 */
import { MAX_DETECTOR_TIMEOUT_MS } from "./contract.js";
import {
  type PolicyRevision,
  policyRevisionSchema,
  validateDetectorDefinition,
  validatePolicyRevision,
} from "./policy.js";

/**
 * Rust's error code for a revision that fails `validate()` / the compile probe.
 * `server/guardrail_policies.rs::write_guardrail_error`, the `None =>` arm.
 */
export const INVALID_GUARDRAIL_POLICY_CODE = "invalid_guardrail_policy";

/**
 * Rust's error code for a body that does not DESERIALIZE as a `PolicyRevision`
 * — `read_guardrail_body`'s `serde_json::from_slice` arm. Kept distinct because
 * Rust keeps it distinct: a missing `name` is a different failure from a `name`
 * that is present and blank.
 */
export const INVALID_REQUEST_BODY_CODE = "invalid_request_body";

export interface PolicyRevisionAdmissionError {
  /** {@link INVALID_GUARDRAIL_POLICY_CODE} or {@link INVALID_REQUEST_BODY_CODE}. */
  readonly code: string;
  /** Dotted path of the offending field, e.g. `checks[0].detector`. */
  readonly field: string;
  /** The underlying validator's message, verbatim. */
  readonly message: string;
  /** `${field}: ${message}` — what a caller puts on the wire. */
  readonly detail: string;
}

export type PolicyRevisionAdmission =
  | { readonly ok: true; readonly revision: PolicyRevision }
  | { readonly ok: false; readonly error: PolicyRevisionAdmissionError };

function refusal(code: string, field: string, message: string): PolicyRevisionAdmission {
  return { ok: false, error: { code, field, message, detail: `${field}: ${message}` } };
}

/**
 * WHICH FIELD made the revision unenforceable.
 *
 * Runs ONLY after {@link validatePolicyRevision} has already refused, and its
 * answer is a label, never a verdict — if it identifies nothing the caller still
 * refuses, with `<root>`. That ordering is deliberate: this function walks the
 * same fields the validator does, and a walk that drifted could otherwise turn
 * into a second, weaker gate. It cannot, because it is unreachable for an
 * ACCEPTED revision.
 *
 * The detector leg is not restated at all — it calls
 * {@link validateDetectorDefinition}, the authoritative per-detector validator.
 */
function locateRevisionField(revision: PolicyRevision): string {
  if (revision.policy_id.trim().length === 0) return "policy_id";
  if (revision.name.trim().length === 0) return "name";
  if (revision.created_by.trim().length === 0) return "created_by";
  if (revision.revision === 0) return "revision";
  if (revision.deadline_ms === 0 || revision.deadline_ms > MAX_DETECTOR_TIMEOUT_MS) {
    return "deadline_ms";
  }
  if (revision.checks.length === 0) return "checks";

  const seen = new Set<string>();
  for (const [index, check] of revision.checks.entries()) {
    if (check.id.trim().length === 0 || seen.has(check.id)) return `checks[${index}].id`;
    seen.add(check.id);
    if (check.sources.length === 0 || new Set(check.sources).size !== check.sources.length) {
      return `checks[${index}].sources`;
    }
    try {
      validateDetectorDefinition(check.detector);
    } catch {
      return `checks[${index}].detector`;
    }
    if (check.fallback_detector !== undefined) {
      if (check.fallback_detector.kind !== "local") return `checks[${index}].fallback_detector`;
      try {
        validateDetectorDefinition(check.fallback_detector);
      } catch {
        return `checks[${index}].fallback_detector`;
      }
    }
  }
  if (!revision.checks.some((check) => check.enabled)) return "checks";
  if (revision.aggregation.type === "threshold") return "aggregation";
  if (revision.on_pass.length === 0) return "on_pass";
  if (revision.on_fail.length === 0) return "on_fail";
  if (revision.on_error.length === 0) return "on_error";
  for (const [name, actions] of [
    ["on_pass", revision.on_pass],
    ["on_fail", revision.on_fail],
    ["on_error", revision.on_error],
  ] as const) {
    if (
      actions.some(
        (action) =>
          (action.kind === "block" ||
            action.kind === "redact" ||
            action.kind === "require_approval" ||
            action.kind === "quarantine") &&
          (!action.code || !action.message),
      )
    ) {
      return name;
    }
  }
  // `validateScope` is the only remaining leg of `validatePolicyRevision`.
  return "scope";
}

export interface PolicyRevisionAdmissionOptions {
  /**
   * Code for the SHAPE (deserialization) leg. Defaults to
   * {@link INVALID_REQUEST_BODY_CODE}, which is right when the candidate came
   * off the wire.
   *
   * A caller admitting a STORED document should pass
   * {@link INVALID_GUARDRAIL_POLICY_CODE} instead: there is no request body to
   * blame, and Rust reaches such a revision through `write_guardrail_error`
   * (which has no serde arm) rather than through `read_guardrail_body`.
   */
  readonly shapeCode?: string;
}

/**
 * Admit a candidate revision, or refuse it with Rust's code and a field path.
 *
 * `candidate` is deliberately `unknown`: this is called both on a request body
 * and on a STORED document (which nothing validated when it was written), and
 * the second caller has no schema guarantee at all.
 */
export function admitPolicyRevision(
  candidate: unknown,
  options: PolicyRevisionAdmissionOptions = {},
): PolicyRevisionAdmission {
  const parsed = policyRevisionSchema.safeParse(candidate);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    const field = issue === undefined ? "<root>" : issue.path.join(".") || "<root>";
    const message = issue === undefined ? "is not a guardrail policy revision" : issue.message;
    return refusal(options.shapeCode ?? INVALID_REQUEST_BODY_CODE, field, message);
  }

  const revision = parsed.data as PolicyRevision;
  try {
    // The authoritative gate — the same call `putRevision` makes on the data
    // plane's boot path, so anything it accepts here it accepts there.
    validatePolicyRevision(revision);
  } catch (error) {
    return refusal(
      INVALID_GUARDRAIL_POLICY_CODE,
      locateRevisionField(revision),
      error instanceof Error ? error.message : String(error),
    );
  }
  return { ok: true, revision };
}
