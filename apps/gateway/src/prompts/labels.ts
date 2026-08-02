/**
 * EDGE resolution of a prompt deployment label (#694).
 *
 * `apps/control-plane` owns the writes; this Worker only reads, once per
 * request that names a label, out of the `PROMPT_LABELS` KV namespace. KV is
 * chosen over D1 for exactly this: the read sits on the inference hot path, and
 * a database round trip per request is what an edge cache exists to remove.
 *
 * ## The tenant fence
 *
 * The scope reaching {@link promptLabelRefFor} comes from the AUTHENTICATED
 * caller, never from the request body, and it is part of the KV KEY. So a
 * request from tenant A cannot address tenant B's pointer even by naming the
 * same template id and the same label — they are different keys. The stored
 * pointer repeats its own tenant/template/label and
 * `readPromptLabelPointer` re-checks them, so a future change to the key format
 * that accidentally collided two scopes would fail the request rather than
 * serve one tenant's system prompt to another.
 *
 * This matters more here than the word "isolation" usually conveys: the system
 * prompt is where a tenant's private instructions and its private data-handling
 * rules live. Serving the wrong one is a data leak dressed up as a config bug.
 *
 * ## Loud failure
 *
 * Every way a label can fail to resolve becomes a DISTINCT refusal
 * ({@link promptLabelRejection}). None of them falls back to "the active
 * revision" or to "no system prompt", which are the two silent failures this
 * feature would otherwise introduce — and both of them answer 200, so nobody
 * would notice until the output quality or the bill moved.
 */
import type { PromptLabelError, PromptLabelPointer, PromptLabelRef } from "@ferrogate/config";
import { normalizePromptLabel, readPromptLabelPointer } from "@ferrogate/config";
import type { CallerScope } from "../inference/ports.js";

/** The KV namespace binding both Workers agree on. */
export const PROMPT_LABELS_BINDING = "PROMPT_LABELS";

/** Bindings this module reads. */
export interface PromptLabelBindings {
  readonly PROMPT_LABELS?: KVNamespace | undefined;
}

/** How a label failed to resolve, in the vocabulary the HTTP layer answers in. */
export interface PromptLabelRejection {
  readonly status: number;
  readonly code: string;
  readonly message: string;
}

/**
 * Map a {@link PromptLabelError} onto a refusal.
 *
 * Four different answers rather than one, because they mean four different
 * things to the operator holding the pager:
 *
 *  - `invalid_label` (400) — the CALLER typed a name that is not a legal label;
 *  - `not_found` (404) — the label is legal and nobody has defined it, which
 *    for a tenant referencing `production` means "your deploy never happened";
 *  - `malformed` / `scope_mismatch` (500) — the STORED pointer is wrong, which
 *    is a platform fault and not something the caller can fix;
 *  - `unavailable` (503) — KV is unreachable or unbound, i.e. retryable.
 *
 * Collapsing them into one 404 would tell an operator whose KV binding is
 * missing that their label does not exist.
 */
export function promptLabelRejection(error: PromptLabelError): PromptLabelRejection {
  switch (error.reason) {
    case "invalid_label":
      return { status: 400, code: "invalid_prompt_label", message: error.message };
    case "not_found":
      return { status: 404, code: "prompt_label_not_found", message: error.message };
    case "unavailable":
      return { status: 503, code: "prompt_labels_unavailable", message: error.message };
    default:
      // `malformed` and `scope_mismatch`. 500 rather than 4xx: the request was
      // well-formed and the stored state is not, and a 4xx would send the
      // caller looking for a mistake they did not make.
      return { status: 500, code: "prompt_label_unreadable", message: error.message };
  }
}

/**
 * Build the lookup reference for an AUTHENTICATED caller.
 *
 * `scope` decides the key space and comes from the credential; nothing in the
 * request body can influence it. A platform-operator credential reads the
 * un-attributed space, which is where labels on operator-owned templates live.
 *
 * Throws {@link PromptLabelError} `invalid_label` for a name that is not a
 * legal label — before any I/O, so a hostile label name cannot be used to probe
 * the namespace.
 */
export function promptLabelRefFor(
  scope: CallerScope,
  templateId: string,
  rawLabel: string,
): PromptLabelRef {
  return {
    tenantId: scope.kind === "tenant" ? scope.tenantId : null,
    templateId,
    label: normalizePromptLabel(rawLabel),
  };
}

/**
 * Resolve `label` to a revision for this caller, or throw
 * {@link PromptLabelError}.
 *
 * Deliberately returns the whole pointer rather than the bare number: the
 * caller logs `updated_at_unix`/`updated_by` when a render fails, and "which
 * label move introduced this" is the first question asked.
 */
export async function resolvePromptLabel(
  env: PromptLabelBindings | undefined,
  scope: CallerScope,
  templateId: string,
  rawLabel: string,
): Promise<PromptLabelPointer> {
  const ref = promptLabelRefFor(scope, templateId, rawLabel);
  return await readPromptLabelPointer(env?.PROMPT_LABELS ?? null, ref);
}
