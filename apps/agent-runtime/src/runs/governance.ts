/**
 * The governance chokepoint every run-creating verb passes through.
 *
 * `crates/agent-worker` refuses to execute ANY handler action — tools, MCP
 * tools, CLI, REST, filesystem, browser, secrets, memory, network egress —
 * until the gateway authorizes it, and an ALLOW binds to a canonical-target
 * fingerprint (`external_actions.rs`, 6.5k LOC). The transport for that gate
 * was a kernel-authenticated Unix socket; the DECISION was the capability
 * envelope. The transport has no CF equivalent; the decision does, and this is
 * it, kept at the API boundary rather than dropped.
 *
 * Four things are enforced here, in this order:
 *
 *  1. **Action identity** (`inventory-edge-control §"action_identity"`) — the
 *     `ClientActionIdentity` is a REQUIRED transport arg in Rust precisely so
 *     that no verb is unattributable. A declared `agent_run_id` /
 *     `parent_action_fingerprint` that is malformed is a 400; an ABSENT one
 *     stays absent and is recorded as NULL — never fabricated (#305/#307).
 *  2. **Capability envelope** — the workload's `required_capabilities` must be
 *     grantable to this workspace.
 *  3. **Isolation** — the Containers/Sandbox-shaped path, with
 *     `enableInternet: false` and `interceptHttps: true` PINNED.
 *  4. **Egress** — requested hosts must be inside the operator's governed
 *     allowlist. An EMPTY allowlist means SEALED: a forgotten configuration
 *     refuses egress rather than permitting it (#471).
 *
 * // PORT-TODO(inventory-edge-control §agent-worker §8.2/§8.4): Firecracker
 * // microVM (KVM + AF_VSOCK guest agent), Docker (`--network none`), and
 * // local-process (`unshare -U -r -m -n -p -f`) isolation have NO CF
 * // equivalent — Workers cannot boot VMs or namespaces. The CF-native tier is
 * // `@cloudflare/sandbox` (`AgentSandbox`, see `wrangler.toml`), which is what
 * // {@link IsolationGrant} describes; the other three remain a self-hosted
 * // Rust/host binary reached through the `/v1/self-hosted-workers/*` lease
 * // protocol, which IS fully implemented here.
 * // PORT-TODO(inventory-edge-control §agent-worker §8.3): Rust also advertises
 * // snapshot support per backend; the CF backend advertises it OFF because
 * // there is no CF primitive. `snapshotSupported: false` records that
 * // honestly rather than silently omitting the capability.
 */
import { HttpError } from "../middleware/errors.js";
import {
  type CapabilityRequest,
  type GovernancePort,
  type IsolationGrant,
  isCanonicalActionFingerprint,
} from "../ports.js";

/** Header the caller declares an existing agent run with (#305). */
export const AGENT_RUN_ID_HEADER = "x-ferrogate-agent-run-id";

/** Header the caller declares the UPSTREAM governed action with (#307). */
export const PARENT_ACTION_FINGERPRINT_HEADER = "x-ferrogate-parent-action-fingerprint";

/** Header carrying the caller's idempotency key (industry-standard spelling). */
export const IDEMPOTENCY_KEY_HEADER = "idempotency-key";

/**
 * Rust `IDEMPOTENCY_KEY_MAX_LEN`. Long enough for a UUID, a ULID, or a caller's
 * `{repo}:{issue}:{attempt}` composite; short enough that the key is never a
 * payload channel.
 */
export const IDEMPOTENCY_KEY_MAX_LEN = 200;

/**
 * Rust `is_addressable_run_id`: a run id must be a bounded, opaque token. This
 * is a *routing* guard — it keeps a path segment from being used to smuggle
 * separators into a Durable Object name or a storage key.
 */
export function isAddressableRunId(runId: string): boolean {
  return runId.length > 0 && runId.length <= 128 && /^[A-Za-z0-9_.:-]+$/.test(runId);
}

/** Rust `declared_agent_run_id`: absent ⇒ `null`; malformed ⇒ 400. */
export function declaredAgentRunId(headers: Headers): string | null {
  const raw = headers.get(AGENT_RUN_ID_HEADER);
  if (raw === null) return null;
  const value = raw.trim();
  if (value === "") return null;
  if (!isAddressableRunId(value)) {
    throw new HttpError(
      400,
      "invalid_agent_run_id_header",
      `${AGENT_RUN_ID_HEADER} must be an opaque token of at most 128 characters`,
    );
  }
  return value;
}

/** Rust `declared_parent_action_fingerprint`: absent ⇒ `null`; malformed ⇒ 400. */
export function declaredParentActionFingerprint(headers: Headers): string | null {
  const raw = headers.get(PARENT_ACTION_FINGERPRINT_HEADER);
  if (raw === null) return null;
  const value = raw.trim();
  if (value === "") return null;
  if (!isCanonicalActionFingerprint(value)) {
    throw new HttpError(
      400,
      "invalid_parent_action_fingerprint_header",
      `${PARENT_ACTION_FINGERPRINT_HEADER} must be sha256:<64 lowercase hex>`,
    );
  }
  return value;
}

/** Read the idempotency key: header wins over the body field (Rust). */
export function idempotencyKey(
  headers: Headers,
  bodyKey: unknown,
): { readonly key: string; readonly source: "header" | "body" } | null {
  const header = headers.get(IDEMPOTENCY_KEY_HEADER)?.trim();
  const candidate =
    header !== undefined && header !== ""
      ? { key: header, source: "header" as const }
      : typeof bodyKey === "string" && bodyKey.trim() !== ""
        ? { key: bodyKey.trim(), source: "body" as const }
        : null;
  if (candidate === null) return null;
  if (candidate.key.length > IDEMPOTENCY_KEY_MAX_LEN) {
    throw new HttpError(
      400,
      "invalid_idempotency_key",
      `idempotency key must be at most ${IDEMPOTENCY_KEY_MAX_LEN} characters`,
    );
  }
  return candidate;
}

/**
 * Run the capability / isolation / egress gate, throwing the governance
 * refusal verbatim. Returns the isolation posture that was actually granted, so
 * the caller can record it as evidence on the run.
 */
export async function authorizeOrThrow(
  governance: GovernancePort,
  request: CapabilityRequest,
): Promise<IsolationGrant> {
  const decision = await governance.authorize(request);
  if (decision.outcome === "deny") {
    throw new HttpError(decision.denial.status, decision.denial.code, decision.denial.message);
  }
  return decision.grant;
}
