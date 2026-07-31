/**
 * The mutation receipt and the render gate (#505).
 *
 * Clean-room port of `ferrogate-control-plane-client::receipt`
 * (inventory-edge-control.md §1.2 / §2.1).
 *
 * The contract this file enforces:
 *
 *  * **Read verbs render the server's body. Mutating verbs can ONLY emit a
 *    `MutationReceipt`.** That is enforced by the type system exactly as it was
 *    in Rust: `renderGate()` hands a mutating verb a `ReceiptRenderer`, which
 *    has no `render(body)` — there is no way to print a raw mutation body.
 *  * Every optional field is **attested**: it carries either a value or a coded
 *    reason for its absence. A receipt is an audit artifact, so a field that is
 *    wrong is worse than a field that is absent.
 *  * `--dry-run` builds a complete receipt without opening a socket.
 */
import type { JsonValue } from "@ferrogate/core";
import type { ClientActionIdentity } from "./action-identity.js";
import {
  ACTION_ID_PREFIX,
  IDENTITY_SCHEMA_VERSION,
  SERVER_TIME_AUTHORITY,
  isWellFormedActionId,
} from "./action-identity.js";
import type { EffectiveContext } from "./context.js";
import { auditAuthSource } from "./context.js";
import { CliError, exitClassFromHttpStatus } from "./errors.js";
import type { ApiResponse, ControlPlaneClient, RequestContext, RequestSpec } from "./ports.js";
import type { VerbDescriptor } from "./registry.js";

export const RECEIPT_OBJECT = "mutation_receipt";
export const RECEIPT_VERSION = 1;
export const ACTION_FINGERPRINT_CONTRACT = "canonical_target_sha256";
export const CLI_ACTION_CLASS = "rest";

/** Stable codes an audit consumer selects on when a field is absent. */
export const ABSENCE = {
  NO_AUDIT_ID_IN_CONTRACT: "endpoint_returns_no_audit_id",
  NO_APPROVAL_ID_IN_CONTRACT: "endpoint_returns_no_approval_id",
  NO_DECISION_IN_CONTRACT: "endpoint_returns_no_policy_decision",
  DRY_RUN_NOT_EXECUTED: "dry_run_not_executed",
  RESOURCE_HAS_NO_REVISIONS: "resource_has_no_revisions",
  RESPONSE_CARRIES_NO_REVISION: "response_carries_no_revision",
  RESPONSE_CARRIES_NO_ROLLBACK_TARGET: "response_carries_no_rollback_target_revision",
  NO_DISTINCT_PRIOR_REVISION: "no_distinct_prior_revision_to_restore",
  NO_PRIOR_REVISION: "no_prior_revision_to_restore",
  NO_OBJECT_VERSION: "response_carries_no_object_version",
  CONTEXT_DECLARES_NO_SCOPE: "context_declares_no_scope",
  SUBJECT_NOT_LOCALLY_RESOLVABLE: "subject_not_locally_resolvable",
  NO_CORRELATION_ID: "response_carries_no_correlation_id",
  COLLECTION_SCOPED_MUTATION: "collection_scoped_mutation",
  RESPONSE_NAMES_NO_RESOURCE_ID: "response_names_no_resource_id",
  NO_IDEMPOTENCY_KEY_SUPPLIED: "request_carries_no_idempotency_key",
  LOCAL_VERB: "local_verb_issues_no_request",
  MUTATION_NOT_APPLIED: "mutation_not_applied",
  MUTATION_OUTCOME_UNKNOWN: "mutation_outcome_unknown",
  REQUEST_NOT_SENT: "request_not_sent",
  NO_HTTP_RESPONSE: "no_authoritative_http_response",
  MUTATION_SUCCEEDED: "mutation_succeeded",
  NO_SERVER_TIME_TOKEN: "no_server_issued_time_token",
  NO_CLIENT_REPORTED_IP: "client_reported_no_ip",
} as const;

// ---------------------------------------------------------------------------
// Attestation
// ---------------------------------------------------------------------------

export interface AbsenceReason {
  readonly code: string;
  readonly detail: string;
}

/** Exactly one of `value` / `absent_reason` is set — never both, never neither. */
export interface Attested<T> {
  readonly value: T | null;
  readonly absent_reason: AbsenceReason | null;
}

export function present<T>(value: T): Attested<T> {
  return { value, absent_reason: null };
}

export function absent<T>(code: string, detail: string): Attested<T> {
  return { value: null, absent_reason: { code, detail } };
}

export function orAbsent<T>(
  value: T | undefined | null,
  code: string,
  detail: string,
): Attested<T> {
  return value === undefined || value === null ? absent<T>(code, detail) : present(value);
}

export function isWellFormed<T>(field: Attested<T>): boolean {
  return (field.value !== null) !== (field.absent_reason !== null);
}

// ---------------------------------------------------------------------------
// Canonical action target
// ---------------------------------------------------------------------------

/** The network target of an action, canonically serialized for fingerprinting. */
export interface CliActionTarget {
  readonly kind: "network";
  readonly scheme: string;
  readonly host: string;
  readonly port: number;
  readonly method: string | null;
  readonly path: string;
  readonly resolved_ips: readonly string[];
  readonly redirects: readonly string[];
}

const DEFAULT_PORTS: Readonly<Record<string, number>> = { "http:": 80, "https:": 443 };

/** Derive the canonical target of a request against an endpoint. */
export function actionTargetForRequest(endpoint: string, spec: RequestSpec): CliActionTarget {
  let url: URL;
  try {
    url = new URL(`${endpoint.replace(/\/+$/, "")}${spec.path}`);
  } catch (error) {
    throw CliError.usage(
      `invalid request URL '${endpoint}${spec.path}': ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  for (const [key, value] of spec.query) url.searchParams.append(key, value);
  if (url.hostname === "") {
    throw CliError.usage(`endpoint '${endpoint}' has no host to attribute`);
  }
  const port = url.port === "" ? DEFAULT_PORTS[url.protocol] : Number(url.port);
  if (port === undefined || !Number.isFinite(port)) {
    throw CliError.usage(
      `endpoint '${endpoint}' uses scheme '${url.protocol.replace(":", "")}', which has no default port`,
    );
  }
  const query = url.searchParams.toString();
  return {
    kind: "network",
    scheme: url.protocol.replace(":", ""),
    host: url.hostname,
    port,
    method: spec.method,
    path: query === "" ? url.pathname : `${url.pathname}?${query}`,
    resolved_ips: [],
    redirects: [],
  };
}

/** The canonical JSON the action fingerprint digests. */
export function canonicalTargetJson(target: CliActionTarget): string {
  return JSON.stringify(target);
}

/** `sha256:<64 lowercase hex>` over the canonical target JSON. */
export async function actionFingerprint(target: CliActionTarget): Promise<string> {
  const bytes = new TextEncoder().encode(canonicalTargetJson(target));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const hex = [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  return `sha256:${hex}`;
}

export function isCanonicalActionFingerprint(value: string): boolean {
  if (!value.startsWith("sha256:")) return false;
  const hex = value.slice("sha256:".length);
  return hex.length === 64 && /^[0-9a-f]+$/.test(hex);
}

// ---------------------------------------------------------------------------
// Receipt shape
// ---------------------------------------------------------------------------

export type MutationOutcome = "applied" | "rejected" | "unknown" | "not_sent";

export function outcomeFromHttpStatus(status: number): MutationOutcome {
  switch (exitClassFromHttpStatus(status)) {
    case "success":
      return "applied";
    case "auth":
    case "not_found_conflict":
    case "validation":
      return "rejected";
    default:
      return "unknown";
  }
}

export type DecisionClass = "allow" | "deny" | "ask" | "degrade";

export interface ReceiptDecision {
  readonly decision: DecisionClass;
  readonly reason: { readonly code: string; readonly detail?: string };
}

export interface ReceiptActor {
  readonly subject: Attested<string>;
  readonly credential_source: string;
  readonly tenant: Attested<string>;
  readonly project: Attested<string>;
  readonly workspace: Attested<string>;
  readonly context_name: Attested<string>;
  readonly endpoint: string;
}

export interface ReceiptTarget {
  readonly group: string;
  readonly resource_id: Attested<string>;
  readonly method: string;
  readonly path: string;
  readonly action: string;
  readonly canonical_target: string;
  readonly action_fingerprint: string;
  readonly action_fingerprint_contract: string;
  readonly object_version: Attested<string>;
}

export interface RollbackPointer {
  readonly command: readonly string[];
  readonly created_revision: Attested<string>;
  readonly restores_revision: Attested<string>;
  readonly note: string;
}

export interface ReceiptFailure {
  readonly class: string;
  readonly code: string;
  readonly message: string;
}

export interface ReceiptCorrelation {
  readonly request_id: Attested<string>;
  readonly trace_id: Attested<string>;
}

export interface ServerIssuedClientSentAt {
  readonly issued_at_unix: number;
  readonly ttl_seconds: number;
  readonly bound_action_id: string;
  readonly authority: string;
}

export interface ReceiptClientIdentity {
  readonly action_id: string;
  readonly client_sent_at: Attested<ServerIssuedClientSentAt>;
  readonly client_clock_unverified_unix: number;
  readonly client_fingerprint: string;
  readonly client_reported_ip: Attested<string>;
}

export interface MutationReceipt {
  readonly object: string;
  readonly receipt_version: number;
  readonly group: string;
  readonly verb: string;
  readonly operation_id: Attested<string>;
  readonly dry_run: boolean;
  readonly outcome: MutationOutcome;
  readonly failure: Attested<ReceiptFailure>;
  readonly actor: ReceiptActor;
  readonly target: ReceiptTarget;
  readonly decision: Attested<ReceiptDecision>;
  readonly approval_id: Attested<string>;
  readonly audit_id: Attested<string>;
  readonly rollback: Attested<RollbackPointer>;
  readonly idempotency_key: Attested<string>;
  readonly client_identity: ReceiptClientIdentity;
  readonly correlation: ReceiptCorrelation;
  readonly http_status: Attested<number>;
  readonly response: JsonValue | null;
}

/** Structural problems with a receipt. An empty list means "well-formed". */
export function validateReceipt(receipt: MutationReceipt): string[] {
  const problems: string[] = [];
  if (receipt.object !== RECEIPT_OBJECT) {
    problems.push(`object must be '${RECEIPT_OBJECT}', got '${receipt.object}'`);
  }
  if (receipt.receipt_version !== RECEIPT_VERSION) {
    problems.push(`receipt_version must be ${RECEIPT_VERSION}, got ${receipt.receipt_version}`);
  }
  if (receipt.target.action_fingerprint_contract !== ACTION_FINGERPRINT_CONTRACT) {
    problems.push(
      `action_fingerprint_contract must be '${ACTION_FINGERPRINT_CONTRACT}', got '${receipt.target.action_fingerprint_contract}'`,
    );
  }
  if (!isCanonicalActionFingerprint(receipt.target.action_fingerprint)) {
    problems.push(
      `action_fingerprint '${receipt.target.action_fingerprint}' is not sha256:<64 lowercase hex>`,
    );
  }
  const check = (name: string, ok: boolean): void => {
    if (!ok) problems.push(`${name} must carry exactly one of value / absent_reason`);
  };
  check("operation_id", isWellFormed(receipt.operation_id));
  check("actor.subject", isWellFormed(receipt.actor.subject));
  check("actor.tenant", isWellFormed(receipt.actor.tenant));
  check("actor.project", isWellFormed(receipt.actor.project));
  check("actor.workspace", isWellFormed(receipt.actor.workspace));
  check("actor.context_name", isWellFormed(receipt.actor.context_name));
  check("target.resource_id", isWellFormed(receipt.target.resource_id));
  check("target.object_version", isWellFormed(receipt.target.object_version));
  check("decision", isWellFormed(receipt.decision));
  check("failure", isWellFormed(receipt.failure));
  check("approval_id", isWellFormed(receipt.approval_id));
  check("audit_id", isWellFormed(receipt.audit_id));
  check("rollback", isWellFormed(receipt.rollback));
  check("idempotency_key", isWellFormed(receipt.idempotency_key));
  check("correlation.request_id", isWellFormed(receipt.correlation.request_id));
  check("correlation.trace_id", isWellFormed(receipt.correlation.trace_id));
  check("http_status", isWellFormed(receipt.http_status));
  check("client_identity.client_sent_at", isWellFormed(receipt.client_identity.client_sent_at));
  check(
    "client_identity.client_reported_ip",
    isWellFormed(receipt.client_identity.client_reported_ip),
  );
  if (!isWellFormedActionId(receipt.client_identity.action_id)) {
    problems.push(
      `client_identity.action_id '${receipt.client_identity.action_id}' is not ${ACTION_ID_PREFIX}<32 lowercase hex>`,
    );
  }
  const fingerprint = receipt.client_identity.client_fingerprint;
  if (!fingerprint.startsWith(IDENTITY_SCHEMA_VERSION)) {
    problems.push(
      `client_identity.client_fingerprint '${fingerprint}' does not start with the '${IDENTITY_SCHEMA_VERSION}' schema marker`,
    );
  }
  if (isCanonicalActionFingerprint(fingerprint)) {
    problems.push(
      `client_identity.client_fingerprint '${fingerprint}' is rendered as a canonical ACTION fingerprint; the client fingerprint describes the client and is not a digest, and an audit consumer joining the two would join the wrong records`,
    );
  }
  const sentAt = receipt.client_identity.client_sent_at.value;
  if (sentAt !== null) {
    if (sentAt.bound_action_id !== receipt.client_identity.action_id) {
      problems.push(
        `client_sent_at is bound to action '${sentAt.bound_action_id}' but this receipt reports action '${receipt.client_identity.action_id}'`,
      );
    }
    if (sentAt.authority !== SERVER_TIME_AUTHORITY) {
      problems.push(
        `client_sent_at.authority must be '${SERVER_TIME_AUTHORITY}', got '${sentAt.authority}'`,
      );
    }
  }
  return problems;
}

function attestedCell<T>(field: Attested<T>): string {
  if (field.value !== null) return String(field.value);
  if (field.absent_reason !== null) return `null (${field.absent_reason.code})`;
  return "null (UNATTESTED)";
}

/** Field/value rows for the human table renderer. */
export function receiptTableRows(receipt: MutationReceipt): (readonly [string, string])[] {
  const failure =
    receipt.failure.value !== null
      ? `${receipt.failure.value.class}/${receipt.failure.value.code}: ${receipt.failure.value.message}`
      : attestedCell(receipt.failure);
  const decision =
    receipt.decision.value !== null
      ? `${receipt.decision.value.decision} (${receipt.decision.value.reason.code})`
      : attestedCell(receipt.decision);
  const sentAt =
    receipt.client_identity.client_sent_at.value !== null
      ? `${receipt.client_identity.client_sent_at.value.issued_at_unix} (${receipt.client_identity.client_sent_at.value.authority})`
      : attestedCell(receipt.client_identity.client_sent_at);
  return [
    ["object", receipt.object],
    ["receipt_version", String(receipt.receipt_version)],
    ["command", `${receipt.group} ${receipt.verb}`],
    ["operation_id", attestedCell(receipt.operation_id)],
    ["dry_run", String(receipt.dry_run)],
    ["outcome", receipt.outcome],
    ["failure", failure],
    ["actor.subject", attestedCell(receipt.actor.subject)],
    ["actor.credential_source", receipt.actor.credential_source],
    ["actor.tenant", attestedCell(receipt.actor.tenant)],
    ["actor.project", attestedCell(receipt.actor.project)],
    ["actor.workspace", attestedCell(receipt.actor.workspace)],
    ["actor.context", attestedCell(receipt.actor.context_name)],
    ["actor.endpoint", receipt.actor.endpoint],
    ["target", `${receipt.target.method} ${receipt.target.path}`],
    ["target.resource_id", attestedCell(receipt.target.resource_id)],
    ["target.action_fingerprint", receipt.target.action_fingerprint],
    ["target.action_fingerprint_contract", receipt.target.action_fingerprint_contract],
    ["target.object_version", attestedCell(receipt.target.object_version)],
    ["decision", decision],
    ["approval_id", attestedCell(receipt.approval_id)],
    ["audit_id", attestedCell(receipt.audit_id)],
    ["idempotency_key", attestedCell(receipt.idempotency_key)],
    ["client.action_id", receipt.client_identity.action_id],
    ["client.client_sent_at (server-issued)", sentAt],
    [
      "client.client_clock_unverified",
      String(receipt.client_identity.client_clock_unverified_unix),
    ],
    ["client.fingerprint", receipt.client_identity.client_fingerprint],
    ["client.reported_ip", attestedCell(receipt.client_identity.client_reported_ip)],
    ["correlation.request_id", attestedCell(receipt.correlation.request_id)],
    ["correlation.trace_id", attestedCell(receipt.correlation.trace_id)],
    ["http_status", attestedCell(receipt.http_status)],
    ["rollback", attestedCell(receipt.rollback)],
  ];
}

// ---------------------------------------------------------------------------
// The render gate
// ---------------------------------------------------------------------------

/** What a verb produced. Exactly one of `body` / `receipt` is set. */
export interface VerbOutput {
  readonly body?: JsonValue;
  readonly receipt?: MutationReceipt;
}

/** Renders a read verb's body verbatim. */
export class BareRenderer {
  constructor(readonly verb: VerbDescriptor) {}
  render(body: JsonValue): VerbOutput {
    return { body };
  }
}

/**
 * Renders a mutating verb's receipt.
 *
 * Deliberately has **no** `render(body)` — a mutating verb cannot print the
 * server's document, only what it attests about the change.
 */
export class ReceiptRenderer {
  constructor(readonly verb: VerbDescriptor) {}
  render(receipt: MutationReceipt): VerbOutput {
    return { receipt };
  }
}

export type RenderGate =
  | { readonly kind: "bare"; readonly renderer: BareRenderer }
  | { readonly kind: "receipt"; readonly renderer: ReceiptRenderer };

/** The only output shape a verb can construct. */
export function renderGate(verb: VerbDescriptor): RenderGate {
  return verb.effect === "mutating"
    ? { kind: "receipt", renderer: new ReceiptRenderer(verb) }
    : { kind: "bare", renderer: new BareRenderer(verb) };
}

// ---------------------------------------------------------------------------
// Revision chains
// ---------------------------------------------------------------------------

/** A family whose objects are revision chains and whose builder accepts the reversal argv. */
export interface RevisionedFamily {
  readonly group: string;
  readonly rollbackVerb: string;
  readonly archiveVerb: string;
  readonly revisionKeys: readonly string[];
  readonly activeRevisionKeys: readonly string[];
  readonly restoresRevisionKeys: readonly string[];
  readonly chainIdKeys: readonly string[];
}

/**
 * Deliberately ONE entry.
 *
 * `agent-schedules` and `gateway-configs` carry a `revision` counter but are not
 * revision chains — they route through plain CRUD, so a pointer built for them
 * emitted a destructive `replace … {"revision":3}`. They now report
 * `resource_has_no_revisions`, which is true of them.
 */
export const REVISIONED_FAMILIES: readonly RevisionedFamily[] = [
  {
    group: "guardrail-policies",
    rollbackVerb: "rollback",
    archiveVerb: "archive",
    revisionKeys: ["revision"],
    activeRevisionKeys: ["active_revision"],
    restoresRevisionKeys: ["previous_active_revision"],
    chainIdKeys: ["policy_id", "id"],
  },
];

export function revisionedFamily(group: string): RevisionedFamily | undefined {
  return REVISIONED_FAMILIES.find((family) => family.group === group);
}

/** One verb whose declared effect deliberately disagrees with its HTTP method. */
export interface MethodEffectException {
  readonly group: string;
  readonly verb: string;
  readonly method: string;
  readonly effect: "read" | "mutating" | "local";
  readonly why: string;
}

export const METHOD_EFFECT_EXCEPTIONS: readonly MethodEffectException[] = [
  {
    group: "mcp-identity",
    verb: "callback",
    method: "GET",
    effect: "mutating",
    why:
      "completeMcpIdentityOauth is a GET only because it is the OAuth redirect target the " +
      "authorization server sends the browser to. It exchanges the authorization code and " +
      "persists an identity grant, so it changes Control-Plane state and owes the operator a " +
      "receipt exactly like `authorize` does.",
  },
];

export function methodEffectException(
  group: string,
  verb: string,
): MethodEffectException | undefined {
  return METHOD_EFFECT_EXCEPTIONS.find(
    (exception) => exception.group === group && exception.verb === verb,
  );
}

// ---------------------------------------------------------------------------
// Planning and executing one mutation
// ---------------------------------------------------------------------------

const AUDIT_ID_KEYS = ["audit_id", "audit_event_id", "audit_log_id"] as const;
const APPROVAL_ID_KEYS = ["approval_id", "tool_approval_id"] as const;
/** Priority is load-bearing: most-specific naming of the changed object first. */
const OBJECT_VERSION_KEYS = [
  "revision",
  "active_revision",
  "version",
  "etag",
  "updated_at_unix",
] as const;
const RESOURCE_ID_KEYS = ["id", "policy_id"] as const;

function lookupString(body: JsonValue, keys: readonly string[]): string | undefined {
  if (body === null || typeof body !== "object" || Array.isArray(body)) return undefined;
  const map = body as Record<string, JsonValue>;
  for (const key of keys) {
    const value = map[key];
    if (typeof value === "string" && value !== "") return value;
    if (typeof value === "number") return String(value);
  }
  return undefined;
}

/** What the caller supplies to plan one mutating invocation. */
export interface MutationPlanInit {
  readonly renderer: ReceiptRenderer;
  readonly group: string;
  readonly spec: RequestSpec;
  readonly segments: readonly string[];
  readonly effective: EffectiveContext;
  readonly identity: ClientActionIdentity;
  readonly dryRun: boolean;
  readonly idempotencyKey?: string;
}

/** The result of executing a plan: the output plus a failure to surface. */
export interface MutationReport {
  readonly output: VerbOutput;
  readonly failure?: CliError;
}

/**
 * One planned mutating invocation.
 *
 * Construction *requires* a `ReceiptRenderer`, which only a mutating verb's
 * render gate produces — a read verb cannot build a plan, and a mutating verb
 * cannot escape one.
 */
export class MutationPlan {
  readonly #init: MutationPlanInit;
  readonly #target: CliActionTarget;
  readonly #fingerprint: string;

  private constructor(init: MutationPlanInit, target: CliActionTarget, fingerprint: string) {
    this.#init = init;
    this.#target = target;
    this.#fingerprint = fingerprint;
  }

  static async create(init: MutationPlanInit): Promise<MutationPlan> {
    const target = actionTargetForRequest(init.effective.endpoint, init.spec);
    return new MutationPlan(init, target, await actionFingerprint(target));
  }

  get spec(): RequestSpec {
    return this.#init.spec;
  }

  get isDryRun(): boolean {
    return this.#init.dryRun;
  }

  /** Build the receipt shell every outcome shares. */
  #shell(outcome: MutationOutcome, overrides: Partial<MutationReceipt> = {}): MutationReceipt {
    const { effective, identity, group, renderer, segments, spec } = this.#init;
    const resourceId = segments.find((segment) => segment.trim() !== "");
    const serverTime = identity.serverIssuedTime();
    const base: MutationReceipt = {
      object: RECEIPT_OBJECT,
      receipt_version: RECEIPT_VERSION,
      group,
      verb: renderer.verb.name,
      operation_id: orAbsent(
        renderer.verb.operationId,
        ABSENCE.LOCAL_VERB,
        "this verb is handled entirely client-side and maps to no operation",
      ),
      dry_run: this.#init.dryRun,
      outcome,
      failure: absent(
        ABSENCE.MUTATION_SUCCEEDED,
        "the request was accepted, so there is no failure to report",
      ),
      actor: {
        subject: absent(
          ABSENCE.SUBJECT_NOT_LOCALLY_RESOLVABLE,
          "the CLI holds a bearer credential, not a resolved subject; the server owns the identity",
        ),
        credential_source: auditAuthSource(effective.auth),
        tenant: orAbsent(
          effective.tenant,
          ABSENCE.CONTEXT_DECLARES_NO_SCOPE,
          "no tenant was selected by flag, env, or context",
        ),
        project: orAbsent(
          effective.project,
          ABSENCE.CONTEXT_DECLARES_NO_SCOPE,
          "no project was declared by the selected context",
        ),
        workspace: orAbsent(
          effective.workspace,
          ABSENCE.CONTEXT_DECLARES_NO_SCOPE,
          "no workspace was declared by the selected context",
        ),
        context_name: orAbsent(
          effective.contextName,
          ABSENCE.CONTEXT_DECLARES_NO_SCOPE,
          "the invocation selected no named context",
        ),
        endpoint: effective.endpoint,
      },
      target: {
        group,
        resource_id: orAbsent(
          resourceId,
          ABSENCE.COLLECTION_SCOPED_MUTATION,
          "the verb addressed the collection, not one object",
        ),
        method: spec.method,
        path: this.#target.path,
        action: CLI_ACTION_CLASS,
        canonical_target: canonicalTargetJson(this.#target),
        action_fingerprint: this.#fingerprint,
        action_fingerprint_contract: ACTION_FINGERPRINT_CONTRACT,
        object_version: absent(
          ABSENCE.NO_OBJECT_VERSION,
          "no response body was available to read an object version from",
        ),
      },
      decision: absent(
        ABSENCE.NO_DECISION_IN_CONTRACT,
        "no Control Plane API operation returns a policy decision envelope",
      ),
      approval_id: absent(
        ABSENCE.NO_APPROVAL_ID_IN_CONTRACT,
        "this endpoint returns no approval identifier",
      ),
      audit_id: absent(
        ABSENCE.NO_AUDIT_ID_IN_CONTRACT,
        "this endpoint returns no audit identifier",
      ),
      rollback: absent(
        ABSENCE.RESOURCE_HAS_NO_REVISIONS,
        "this resource family is not a revision chain, so there is no reversal command to name",
      ),
      idempotency_key: orAbsent(
        this.#init.idempotencyKey,
        ABSENCE.NO_IDEMPOTENCY_KEY_SUPPLIED,
        "the invocation supplied no idempotency key",
      ),
      client_identity: {
        action_id: identity.actionId,
        client_sent_at:
          serverTime === undefined
            ? absent(
                ABSENCE.NO_SERVER_TIME_TOKEN,
                "the server issued no time token for this action, so no authoritative send time exists",
              )
            : present({
                issued_at_unix: serverTime.issuedAtUnix,
                ttl_seconds: serverTime.ttlSeconds,
                bound_action_id: serverTime.boundActionId,
                authority: SERVER_TIME_AUTHORITY,
              }),
        client_clock_unverified_unix: identity.clientClockUnix,
        client_fingerprint: renderFingerprintOf(identity),
        client_reported_ip: orAbsent(
          identity.fingerprint.reportedIp,
          ABSENCE.NO_CLIENT_REPORTED_IP,
          "the operator disclosed no client address",
        ),
      },
      correlation: {
        request_id: absent(ABSENCE.NO_CORRELATION_ID, "no response carried a request id"),
        trace_id: absent(ABSENCE.NO_CORRELATION_ID, "no response carried a trace id"),
      },
      http_status: absent(ABSENCE.NO_HTTP_RESPONSE, "no authoritative HTTP response was received"),
      response: null,
    };
    return { ...base, ...overrides };
  }

  /** Build the receipt for `--dry-run`: complete, and provably not executed. */
  dryRun(): VerbOutput {
    const receipt = this.#shell("not_sent", {
      failure: absent(
        ABSENCE.DRY_RUN_NOT_EXECUTED,
        "--dry-run built the plan without opening a socket, so nothing could fail",
      ),
      http_status: absent(ABSENCE.REQUEST_NOT_SENT, "--dry-run sends no request"),
    });
    return this.#init.renderer.render(receipt);
  }

  /** Send the mutation and attest whatever came back — including a refusal. */
  async send(client: ControlPlaneClient, requestContext: RequestContext): Promise<MutationReport> {
    let response: ApiResponse;
    try {
      response = await client.send(this.#init.spec, requestContext);
    } catch (error) {
      const failure = error instanceof CliError ? error : CliError.transport(String(error));
      const status = failure.api?.httpStatus;
      const outcome = status === undefined ? "unknown" : outcomeFromHttpStatus(status);
      const receipt = this.#shell(outcome, {
        failure: present({
          class: failure.exitClass(),
          code: failure.api?.code ?? failure.kind,
          message: failure.message,
        }),
        http_status:
          status === undefined
            ? absent(ABSENCE.NO_HTTP_RESPONSE, "the request never reached an authoritative answer")
            : present(status),
        correlation: {
          request_id: orAbsent(
            failure.api?.requestId,
            ABSENCE.NO_CORRELATION_ID,
            "the error carried no request id",
          ),
          trace_id: orAbsent(
            failure.api?.traceId,
            ABSENCE.NO_CORRELATION_ID,
            "the error carried no trace id",
          ),
        },
      });
      return { output: this.#init.renderer.render(receipt), failure };
    }

    const body = response.body;
    const receipt = this.#shell(outcomeFromHttpStatus(response.status), {
      http_status: present(response.status),
      target: {
        ...this.#shell("applied").target,
        resource_id: orAbsent(
          this.#init.segments.find((segment) => segment.trim() !== "") ??
            lookupString(body, RESOURCE_ID_KEYS),
          ABSENCE.RESPONSE_NAMES_NO_RESOURCE_ID,
          "neither the command line nor the response named the mutated object",
        ),
        object_version: orAbsent(
          lookupString(body, OBJECT_VERSION_KEYS),
          ABSENCE.NO_OBJECT_VERSION,
          "the response carries no field naming the changed object's version",
        ),
      },
      audit_id: orAbsent(
        lookupString(body, AUDIT_ID_KEYS),
        ABSENCE.NO_AUDIT_ID_IN_CONTRACT,
        "this endpoint returns no audit identifier",
      ),
      approval_id: orAbsent(
        lookupString(body, APPROVAL_ID_KEYS),
        ABSENCE.NO_APPROVAL_ID_IN_CONTRACT,
        "this endpoint returns no approval identifier",
      ),
      rollback: this.#rollbackPointer(body),
      correlation: {
        request_id: orAbsent(
          response.requestId,
          ABSENCE.NO_CORRELATION_ID,
          "the response carried no request id",
        ),
        trace_id: orAbsent(
          response.traceId,
          ABSENCE.NO_CORRELATION_ID,
          "the response carried no trace id",
        ),
      },
      response: body,
    });
    return { output: this.#init.renderer.render(receipt) };
  }

  /**
   * The reversal command, derived only from server-supplied revision evidence.
   *
   * A client must NOT fabricate a rollback target by decrementing the active
   * revision — a wrong reversal command in an audit artifact is worse than an
   * absent one.
   */
  #rollbackPointer(body: JsonValue): Attested<RollbackPointer> {
    const family = revisionedFamily(this.#init.group);
    if (family === undefined) {
      return absent(
        ABSENCE.RESOURCE_HAS_NO_REVISIONS,
        "this resource family is not a revision chain, so there is no reversal command to name",
      );
    }
    const chainId =
      lookupString(body, family.chainIdKeys) ??
      this.#init.segments.find((segment) => segment.trim() !== "");
    if (chainId === undefined) {
      return absent(
        ABSENCE.RESPONSE_NAMES_NO_RESOURCE_ID,
        "the response named no revision chain to reverse",
      );
    }
    const created =
      lookupString(body, family.revisionKeys) ?? lookupString(body, family.activeRevisionKeys);
    const restores = lookupString(body, family.restoresRevisionKeys);

    if (restores !== undefined) {
      return present({
        command: [
          "ferrogate",
          "ctl",
          family.group,
          family.rollbackVerb,
          chainId,
          "--data",
          JSON.stringify({ revision: Number(restores) }),
        ],
        created_revision: orAbsent(
          created,
          ABSENCE.RESPONSE_CARRIES_NO_REVISION,
          "the response named no newly created revision",
        ),
        restores_revision: present(restores),
        note:
          "revisions are append-only: this rolls the live binding back to the named revision " +
          "rather than deleting anything",
      });
    }
    if (created !== undefined) {
      return present({
        command: ["ferrogate", "ctl", family.group, family.archiveVerb, chainId, created],
        created_revision: present(created),
        restores_revision: absent(
          ABSENCE.NO_PRIOR_REVISION,
          "the response named no prior revision to restore, so the reversal retires the created one",
        ),
        note: "retires the revision this command created; the chain itself stays append-only",
      });
    }
    return absent(
      ABSENCE.RESPONSE_CARRIES_NO_ROLLBACK_TARGET,
      "the response carried neither a created revision nor a rollback target",
    );
  }
}

function renderFingerprintOf(identity: ClientActionIdentity): string {
  // Re-rendered here (rather than stored) so a receipt can never disagree with
  // the header the request actually carried.
  const headers = identity.headers();
  return headers["x-ferrogate-client-fingerprint"] ?? IDENTITY_SCHEMA_VERSION;
}
