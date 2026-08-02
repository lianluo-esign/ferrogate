/**
 * Prompt DEPLOYMENT LABELS — the `label → revision` pointer, and the KV key it
 * lives under.
 *
 * A prompt template is versioned, but until this module there was no way to say
 * "the revision production is currently serving". Shipping a prompt change
 * therefore meant editing the operator config table and redeploying. A label
 * (`production`, `staging`, or any operator-chosen name) is that missing
 * indirection: moving it is a control-plane call, and the data plane reads the
 * pointer out of KV on the hot path rather than re-reading D1.
 *
 * ## Why the key derivation lives HERE and not in either app
 *
 * `apps/control-plane` WRITES the pointer and `apps/gateway` READS it. If each
 * derived its own key, a rename on one side would not fail a build or a test —
 * it would silently make every lookup miss, and a miss on the read side is
 * indistinguishable from "the operator has not labelled this template yet". So
 * both sides call {@link promptLabelPointerKey}, and the one function is the
 * contract.
 *
 * ## The tenant fence
 *
 * The scope is part of the KEY, not merely part of the value: tenant B's
 * `production` and tenant A's `production` are different KV entries, so no
 * amount of confusion downstream can make one resolve to the other. The stored
 * pointer ALSO carries its own `tenant_id`/`template_id`/`label`, and
 * {@link promptLabelPointerMatches} re-checks them after the read — defence in
 * depth against the one failure this design cannot otherwise see, a key
 * collision produced by a future change to the key format. Cross-tenant prompt
 * bleed is not a cosmetic bug: the system prompt is where a tenant's private
 * instructions live.
 *
 * Every component is `encodeURIComponent`-escaped before it is joined, which is
 * what makes the separator unforgeable — `/` and `:` both escape, so a tenant
 * id or template id containing a separator cannot climb into another scope's
 * key space.
 *
 * ## Loud failure, never a silent default
 *
 * {@link PromptLabelError} exists so that "this label does not exist" cannot be
 * collapsed into `undefined` and then into an empty prompt. A silently-empty
 * system prompt is the kind of failure nobody notices until the bill or the
 * output quality moves, so every non-resolution here is an ERROR carrying a
 * machine-readable {@link PromptLabelErrorReason}, and both call sites turn it
 * into a distinct 4xx/5xx.
 */
import { z } from "zod";

/**
 * Key-space version. Bumping it invalidates every pointer at once, which is the
 * correct behaviour for a format change: a stale pointer read with new
 * expectations is worse than a miss, because a miss is loud.
 */
export const PROMPT_LABEL_KEY_VERSION = "v1";

/** KV key prefix — `list({ prefix })` over it enumerates one scope's labels. */
export const PROMPT_LABEL_KEY_PREFIX = `prompt-label/${PROMPT_LABEL_KEY_VERSION}`;

/**
 * The two labels the product names. Neither is reserved and neither is created
 * implicitly — an operator may use any name — but they are exported so the two
 * apps and their tests spell them the same way.
 */
export const PROMPT_LABEL_PRODUCTION = "production";
export const PROMPT_LABEL_STAGING = "staging";

/**
 * A label name, after {@link normalizePromptLabel}.
 *
 * Lowercase because a label is an identifier an operator types in a URL, and
 * `Production` resolving to nothing while `production` resolves is a trap. The
 * leading character is constrained so a name can never begin with a separator
 * or look like a flag.
 */
export const promptLabelNameSchema = z
  .string()
  .min(1, "prompt label must not be empty")
  .max(64, "prompt label must be at most 64 characters")
  .regex(
    /^[a-z0-9][a-z0-9._-]*$/,
    "prompt label must start with a letter or digit and contain only lowercase letters, digits, '.', '_' and '-'",
  );

/** Raised by {@link normalizePromptLabel} and the KV resolver. */
export type PromptLabelErrorReason =
  /** The label name is not a legal label at all. */
  | "invalid_label"
  /** No pointer exists for this scope + template + label. */
  | "not_found"
  /** A pointer exists but is not a pointer this version can read. */
  | "malformed"
  /** The stored pointer does not describe the scope it was read for. */
  | "scope_mismatch"
  /** No KV namespace is bound, or the read failed. */
  | "unavailable";

/**
 * The one error type both apps map to an HTTP refusal.
 *
 * `reason` rather than message-sniffing: the control plane and the gateway pick
 * different status codes per reason, and matching on prose is how those drift.
 */
export class PromptLabelError extends Error {
  override readonly name = "PromptLabelError";
  readonly reason: PromptLabelErrorReason;

  constructor(reason: PromptLabelErrorReason, message: string) {
    super(message);
    this.reason = reason;
  }
}

/**
 * Trim + lowercase + validate. THROWS rather than returning `null`, because a
 * label that failed to normalize must not be able to flow onward as an empty
 * string and match a key nobody wrote.
 */
export function normalizePromptLabel(raw: string): string {
  const candidate = raw.trim().toLowerCase();
  const parsed = promptLabelNameSchema.safeParse(candidate);
  if (!parsed.success) {
    throw new PromptLabelError(
      "invalid_label",
      parsed.error.issues[0]?.message ?? "prompt label is invalid",
    );
  }
  return parsed.data;
}

/**
 * Which credential's label space a lookup is confined to.
 *
 * Mirrors the `CallerScope` both Workers already carry (`platform_operator` or
 * exactly one tenant), restated here so `@ferrogate/config` does not have to
 * depend on an app. `tenantId` of `null` means the platform-operator space,
 * which is a SEPARATE space and not a wildcard: an operator-owned label is
 * never served to a tenant, and a tenant's label is never served to the
 * operator, because neither can name the other's key.
 */
export interface PromptLabelRef {
  /** `null` = the platform-operator label space. */
  readonly tenantId: string | null;
  readonly templateId: string;
  /** Already normalized (see {@link normalizePromptLabel}). */
  readonly label: string;
}

/** `encodeURIComponent` escapes `/` and `:`, which is what fences the segments. */
function segment(value: string): string {
  return encodeURIComponent(value);
}

/**
 * The scope segment.
 *
 * `operator` and `tenant/<id>` differ in segment COUNT as well as in text, and
 * the tenant id is escaped, so no tenant id can ever produce the operator key
 * — not even the literal id `"operator"`, which escapes to `operator` but sits
 * one segment deeper behind the `tenant` discriminator.
 */
function scopeSegment(tenantId: string | null): string {
  return tenantId === null ? "operator" : `tenant/${segment(tenantId)}`;
}

/**
 * The KV key a pointer lives under.
 *
 * Called by BOTH apps. Changing it without bumping
 * {@link PROMPT_LABEL_KEY_VERSION} silently orphans every pointer already
 * written, so the version constant is part of the prefix rather than something
 * a caller has to remember to include.
 */
export function promptLabelPointerKey(ref: PromptLabelRef): string {
  return `${PROMPT_LABEL_KEY_PREFIX}/${scopeSegment(ref.tenantId)}/${segment(ref.templateId)}/${segment(ref.label)}`;
}

/** Prefix that enumerates every label of ONE template within ONE scope. */
export function promptLabelTemplatePrefix(tenantId: string | null, templateId: string): string {
  return `${PROMPT_LABEL_KEY_PREFIX}/${scopeSegment(tenantId)}/${segment(templateId)}/`;
}

/**
 * The stored pointer.
 *
 * `.strict()` on purpose: an unknown member means the writer is a version this
 * reader does not understand, and guessing at a pointer that decides which
 * prompt a tenant's traffic runs is not a risk worth taking for forward
 * compatibility. A format change bumps {@link PROMPT_LABEL_KEY_VERSION}.
 *
 * `tenant_id` is nullable and REQUIRED — it is written even when it duplicates
 * the key, because {@link promptLabelPointerMatches} needs something to compare
 * against that did not come from the key it was fetched with.
 */
export const promptLabelPointerSchema = z
  .object({
    tenant_id: z.string().nullable(),
    template_id: z.string().min(1),
    label: z.string().min(1),
    /** 1-based, matching `PromptTemplateVersion.revision`. */
    revision: z.number().int().positive(),
    updated_at_unix: z.number().int().nonnegative(),
    /** The api-key id / subject that last moved the label, when known. */
    updated_by: z.string().nullable().default(null),
  })
  .strict();

export type PromptLabelPointer = z.infer<typeof promptLabelPointerSchema>;

/** Does a stored pointer actually describe the reference it was read for? */
export function promptLabelPointerMatches(
  pointer: PromptLabelPointer,
  ref: PromptLabelRef,
): boolean {
  return (
    pointer.tenant_id === ref.tenantId &&
    pointer.template_id === ref.templateId &&
    pointer.label === ref.label
  );
}

/** The KV surface this module needs — narrower than `KVNamespace` on purpose. */
export interface PromptLabelKv {
  get(key: string, type: "text"): Promise<string | null>;
  put(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;
  list(options: { prefix: string }): Promise<{ keys: { name: string }[] }>;
}

/**
 * Read a pointer, or THROW.
 *
 * There is deliberately no `null` return and no default. Every way this can
 * fail to produce a pointer is a {@link PromptLabelError} with a reason the
 * caller turns into a distinct refusal, because the alternative — falling back
 * to "the active revision" or to no prompt at all — is exactly the silent
 * failure this feature exists to prevent.
 */
export async function readPromptLabelPointer(
  kv: PromptLabelKv | undefined | null,
  ref: PromptLabelRef,
): Promise<PromptLabelPointer> {
  if (kv === undefined || kv === null) {
    throw new PromptLabelError(
      "unavailable",
      "prompt label storage is not configured on this deployment",
    );
  }

  const key = promptLabelPointerKey(ref);
  let raw: string | null;
  try {
    raw = await kv.get(key, "text");
  } catch (error) {
    // A KV outage must not degrade into "no label", which would silently serve
    // whatever the un-labelled path serves.
    throw new PromptLabelError(
      "unavailable",
      `prompt label ${ref.label} could not be read: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (raw === null) {
    throw new PromptLabelError(
      "not_found",
      `prompt label ${ref.label} is not defined for prompt template ${ref.templateId}`,
    );
  }

  let decoded: unknown;
  try {
    decoded = JSON.parse(raw);
  } catch {
    throw new PromptLabelError("malformed", `prompt label ${ref.label} is not readable`);
  }
  const parsed = promptLabelPointerSchema.safeParse(decoded);
  if (!parsed.success) {
    throw new PromptLabelError("malformed", `prompt label ${ref.label} is not readable`);
  }
  if (!promptLabelPointerMatches(parsed.data, ref)) {
    // Unreachable while the key derivation above is the only writer — which is
    // precisely why it is checked. If it ever fires, a pointer was served
    // across a scope boundary and the request must die rather than render.
    throw new PromptLabelError(
      "scope_mismatch",
      `prompt label ${ref.label} does not belong to this caller`,
    );
  }
  return parsed.data;
}
