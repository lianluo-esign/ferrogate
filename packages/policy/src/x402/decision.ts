/**
 * The pure, deterministic x402 payment-authorization decision (port of
 * `ferrogate-policy` `x402_spend.rs`, issue #351 — DEPRIORITIZED per inventory §2.1).
 *
 * Given a validated policy, a wire-shaped payment request, and a caller-supplied
 * spend snapshot, returns an immutable {@link PaymentAuthorization}. No signer,
 * storage, or network I/O; the same inputs always yield the same output.
 * Evaluation fails closed: every ambiguity is a Deny with a stable reason code.
 */
import { Sha256Builder } from "./sha256.js";
import {
  canonicalUrl,
  policyNetworkCaip2,
  policyNetworkEquals,
  resourceRuleMatches,
  snapshot as makeSnapshot,
  type AtomicAmount,
  type ConversionSnapshot,
  type Credits,
  type PolicyNetwork,
  type ResourceRule,
  type ValidatedX402SpendPolicy,
  type X402SpendPolicy,
  U64_MAX,
} from "./config.js";
import {
  challengeHashHex,
  networkCaip2,
  type PaymentIntent,
  type SelectedPayment,
} from "./wire.js";

/** The three-valued payment decision. */
export type PaymentDecision =
  | { kind: "allow" }
  | { kind: "approval_required"; thresholdCredits: bigint }
  | { kind: "deny" };

// Stable reason codes — part of the decision contract; must not change.
export const REASON_ALLOWED = "x402_allowed";
export const REASON_DISABLED = "x402_disabled";
export const REASON_NETWORK_NOT_ALLOWED = "x402_network_not_allowed";
export const REASON_MINT_NOT_ALLOWED = "x402_mint_not_allowed";
export const REASON_RECIPIENT_NOT_ALLOWED = "x402_recipient_not_allowed";
export const REASON_RESOURCE_MISMATCH = "x402_resource_mismatch";
export const REASON_RESOURCE_NOT_ALLOWED = "x402_resource_not_allowed";
export const REASON_AMOUNT_BELOW_MIN = "x402_amount_below_min";
export const REASON_ATOMIC_CAP_EXCEEDED = "x402_atomic_cap_exceeded";
export const REASON_CONVERSION_UNAVAILABLE = "x402_conversion_unavailable";
export const REASON_OVER_PER_PAYMENT_CAP = "x402_over_per_payment_cap";
export const REASON_OVER_RUN_CAP = "x402_over_run_cap";
export const REASON_OVER_WINDOW_CAP = "x402_over_window_cap";
export const REASON_APPROVAL_REQUIRED = "x402_approval_required";
export const REASON_INTENT_MISMATCH = "x402_intent_mismatch";
export const REASON_CONVERSION_EXPIRED = "x402_conversion_expired";

/** Domain-separation tag for {@link PaymentAuthorization.decisionHashHex}. */
export const PAYMENT_DECISION_HASH_DOMAIN = "ferrogate.x402.payment-decision.v1";

/** The scope chain a payment is evaluated at. `tenantId` mandatory. */
export interface SpendScope {
  tenantId: string;
  projectId?: string;
  workspaceId?: string;
  keyId?: string;
  runId?: string;
}

/** The scope a decision was evaluated at, owned so it can be persisted. */
export interface AuthorizedScope {
  tenantId: string;
  projectId?: string;
  workspaceId?: string;
  keyId?: string;
  runId?: string;
}

function authorizedScope(scope: SpendScope): AuthorizedScope {
  return {
    tenantId: scope.tenantId,
    projectId: scope.projectId,
    workspaceId: scope.workspaceId,
    keyId: scope.keyId,
    runId: scope.runId,
  };
}

/** A caller-supplied snapshot of already-committed spend (from the durable ledger). */
export interface SpendSnapshot {
  runSpentCredits: bigint;
  windowSpentCredits: bigint;
  /**
   * The caller's wall clock (unix second), used ONLY to test the conversion
   * rule's validity window. `undefined` means the caller offered no clock — a
   * policy whose rule declares an expiry then denies (unprovable freshness).
   */
  nowUnix?: number;
}

/** The default zero-spend snapshot with no clock. */
export function emptySpendSnapshot(): SpendSnapshot {
  return { runSpentCredits: 0n, windowSpentCredits: 0n };
}

/** A payment-authorization request. */
export interface PaymentAuthorizationRequest {
  selected: SelectedPayment;
  intent: PaymentIntent;
  scope: SpendScope;
}

/**
 * The immutable, self-describing result of evaluating one payment authorization.
 * Every field is private and reachable only through an accessor, and
 * {@link authorizeX402Payment} is the only constructor — mirroring the crate's
 * sealed-field immutability so "the decision policy made" and "the decision the
 * sink recorded" are the same object.
 */
export class PaymentAuthorization {
  /** @internal */
  constructor(
    private readonly _decision: PaymentDecision,
    private readonly _reasonCode: string,
    private readonly _message: string,
    private readonly _policyRevision: bigint,
    private readonly _networkCaip2: string,
    private readonly _mint: string,
    private readonly _recipient: string,
    private readonly _resourceUrl: string,
    private readonly _authorizedResourceUrl: string,
    private readonly _httpMethod: string,
    private readonly _requestBodyHashHex: string,
    private readonly _intentHashHex: string,
    private readonly _scope: AuthorizedScope,
    private readonly _challengeHashHex: string,
    private readonly _conversion: ConversionSnapshot,
    private readonly _matchedResource: ResourceRule | undefined,
  ) {}

  decision(): PaymentDecision {
    return this._decision;
  }
  reasonCode(): string {
    return this._reasonCode;
  }
  message(): string {
    return this._message;
  }
  policyRevision(): bigint {
    return this._policyRevision;
  }
  networkCaip2(): string {
    return this._networkCaip2;
  }
  mint(): string {
    return this._mint;
  }
  recipient(): string {
    return this._recipient;
  }
  resourceUrl(): string {
    return this._resourceUrl;
  }
  authorizedResourceUrl(): string {
    return this._authorizedResourceUrl;
  }
  httpMethod(): string {
    return this._httpMethod;
  }
  requestBodyHashHex(): string {
    return this._requestBodyHashHex;
  }
  intentHashHex(): string {
    return this._intentHashHex;
  }
  scope(): AuthorizedScope {
    return this._scope;
  }
  challengeHashHex(): string {
    return this._challengeHashHex;
  }
  conversion(): ConversionSnapshot {
    return this._conversion;
  }
  matchedResource(): ResourceRule | undefined {
    return this._matchedResource;
  }

  /** True iff the decision is Allow. */
  isAllowed(): boolean {
    return this._decision.kind === "allow";
  }

  /** The computed internal credits, if the conversion succeeded. */
  computedCredits(): Credits | undefined {
    return this._conversion.computedCredits;
  }

  /**
   * Deterministic SHA-256 (hex) over the load-bearing content of this decision.
   * The human-readable message is deliberately excluded (not load-bearing).
   */
  decisionHashHex(): string {
    const decision =
      this._decision.kind === "approval_required"
        ? `approval_required:${this._decision.thresholdCredits}`
        : this._decision.kind;
    const atomic = this._conversion.atomicAmount.toString();
    const credits =
      this._conversion.computedCredits !== undefined
        ? `credits:${this._conversion.computedCredits}`
        : "credits:none";
    const matched =
      this._matchedResource !== undefined
        ? `${this._matchedResource.origin}|${this._matchedResource.pathPrefix}`
        : "";
    const h = new Sha256Builder();
    for (const part of [
      PAYMENT_DECISION_HASH_DOMAIN,
      decision,
      this._reasonCode,
      this._policyRevision.toString(),
      this._networkCaip2,
      this._mint,
      this._recipient,
      this._resourceUrl,
      this._authorizedResourceUrl,
      this._httpMethod,
      this._requestBodyHashHex,
      this._intentHashHex,
      this._challengeHashHex,
      atomic,
      credits,
      this._conversion.version,
      matched,
    ]) {
      h.pushStr(part).pushByte(0);
    }
    return h.digestHex();
  }
}

/**
 * Pure, deterministic payment-authorization decision (issue #351). Fails closed:
 * every check defaults to Deny and any ambiguity is a Deny with a stable code.
 */
export function authorizeX402Payment(
  policy: ValidatedX402SpendPolicy,
  request: PaymentAuthorizationRequest,
  spent: SpendSnapshot,
): PaymentAuthorization {
  const p = policy.policy();
  const { selected, intent } = request;
  const atomic: AtomicAmount = selected.atomicAmount;
  const conversion = makeSnapshot(p.conversion, atomic);
  const scope = authorizedScope(request.scope);
  const intentHashHex = intent.intentHashHex();
  const requestBodyHashHex = intent.requestBodyHashHex();

  const build = (
    decision: PaymentDecision,
    reasonCode: string,
    message: string,
    matchedResource: ResourceRule | undefined,
  ): PaymentAuthorization =>
    new PaymentAuthorization(
      decision,
      reasonCode,
      message,
      p.revision,
      networkCaip2(selected.network),
      selected.mint,
      selected.recipient,
      selected.resourceUrl,
      intent.authorizedResourceUrl(),
      intent.httpMethod(),
      requestBodyHashHex,
      intentHashHex,
      scope,
      challengeHashHex(selected),
      conversion,
      matchedResource,
    );
  const deny = (reasonCode: string, message: string): PaymentAuthorization =>
    build({ kind: "deny" }, reasonCode, message, undefined);

  // 0. Intent binding — checked before the master switch (incoherent input is a
  //    refusal regardless of whether the scope has payments enabled).
  const mismatch = intent.bindingMismatch(selected);
  if (mismatch !== undefined) {
    return deny(REASON_INTENT_MISMATCH, `payment intent does not match the challenge (${mismatch} differs)`);
  }

  // 1. Master switch.
  if (!p.enabled) {
    return deny(REASON_DISABLED, "x402 spending is disabled for this scope");
  }

  // 2. Network allowlist.
  const network: PolicyNetwork = { network: selected.network };
  if (!p.allowedNetworks.some((n) => policyNetworkEquals(n, network))) {
    return deny(REASON_NETWORK_NOT_ALLOWED, `network ${policyNetworkCaip2(network)} is not allowlisted`);
  }

  // 3. (network, mint) allowlist.
  const mintAllowed = p.allowedAssets.some(
    (a) => policyNetworkEquals(a.network, network) && a.mint === selected.mint,
  );
  if (!mintAllowed) {
    return deny(REASON_MINT_NOT_ALLOWED, `mint ${selected.mint} on ${policyNetworkCaip2(network)} is not allowlisted`);
  }

  // 4. Recipient allowlist.
  if (!p.allowedRecipients.some((r) => r === selected.recipient)) {
    return deny(REASON_RECIPIENT_NOT_ALLOWED, `recipient ${selected.recipient} is not allowlisted`);
  }

  // 5. Resource binding: the challenge's resource must equal the already-authorized
  //    egress URL (no redirect), and that URL must be covered by a resource rule.
  const challenge = canonicalUrl(selected.resourceUrl);
  const authorized = canonicalUrl(intent.authorizedResourceUrl());
  if (challenge === undefined || authorized === undefined || !canonicalUrlEquals(challenge, authorized)) {
    return deny(
      REASON_RESOURCE_MISMATCH,
      `challenge resource ${JSON.stringify(selected.resourceUrl)} does not match authorized egress ${JSON.stringify(
        intent.authorizedResourceUrl(),
      )}`,
    );
  }
  const matched = p.allowedResources.find((rule) => resourceRuleMatches(rule, authorized));
  if (matched === undefined) {
    return deny(
      REASON_RESOURCE_NOT_ALLOWED,
      `authorized resource ${intent.authorizedResourceUrl()} is not covered by any resource rule`,
    );
  }

  return evaluateAmount(p, conversion, atomic, spent, build, matched);
}

function canonicalUrlEquals(
  a: import("./config.js").CanonicalUrl,
  b: import("./config.js").CanonicalUrl,
): boolean {
  return (
    a.origin.scheme === b.origin.scheme &&
    a.origin.authority === b.origin.authority &&
    a.path === b.path
  );
}

/** Amount / cap / approval evaluation, reached only after binding has passed. */
function evaluateAmount(
  p: X402SpendPolicy,
  conversion: ConversionSnapshot,
  atomic: AtomicAmount,
  spent: SpendSnapshot,
  build: (
    decision: PaymentDecision,
    reasonCode: string,
    message: string,
    matchedResource: ResourceRule | undefined,
  ) => PaymentAuthorization,
  rule: ResourceRule,
): PaymentAuthorization {
  const deny = (code: string, msg: string): PaymentAuthorization =>
    build({ kind: "deny" }, code, msg, undefined);
  const caps = p.caps;

  // 6. Atomic bounds (direct, independent of the credit conversion).
  if (caps.minAtomicPerPayment !== undefined && atomic < caps.minAtomicPerPayment) {
    return deny(REASON_AMOUNT_BELOW_MIN, `atomic amount ${atomic} is below the minimum ${caps.minAtomicPerPayment}`);
  }
  if (caps.maxAtomicPerPayment !== undefined && atomic > caps.maxAtomicPerPayment) {
    return deny(REASON_ATOMIC_CAP_EXCEEDED, `atomic amount ${atomic} exceeds the hard cap ${caps.maxAtomicPerPayment}`);
  }

  // 7. Conversion freshness: a rate past its window — or one whose freshness the
  //    caller cannot demonstrate — denies before any cap is consulted.
  if (conversion.expiresAtUnix !== undefined) {
    if (spent.nowUnix === undefined) {
      return deny(
        REASON_CONVERSION_EXPIRED,
        `conversion rule version ${JSON.stringify(
          conversion.version,
        )} declares a validity window but the caller supplied no clock to check it against`,
      );
    }
    if (spent.nowUnix >= conversion.expiresAtUnix) {
      return deny(
        REASON_CONVERSION_EXPIRED,
        `conversion rule version ${JSON.stringify(conversion.version)} expired at ${conversion.expiresAtUnix} (now ${spent.nowUnix})`,
      );
    }
  }

  // 8. Conversion to credits. Overflow / impossible ratio denies.
  const credits = conversion.computedCredits;
  if (credits === undefined) {
    return deny(
      REASON_CONVERSION_UNAVAILABLE,
      `atomic amount ${atomic} could not be converted to credits (overflow or impossible ratio, version ${JSON.stringify(
        conversion.version,
      )})`,
    );
  }

  // 9. Per-payment credit cap.
  if (caps.maxCreditsPerPayment !== undefined && credits > caps.maxCreditsPerPayment) {
    return deny(
      REASON_OVER_PER_PAYMENT_CAP,
      `payment costs ${credits} credits, over the per-payment cap ${caps.maxCreditsPerPayment}`,
    );
  }

  // 10. Per-run cap: checked add (overflow denies rather than wrapping).
  if (caps.maxCreditsPerRun !== undefined) {
    const total = spent.runSpentCredits + credits;
    if (total > U64_MAX) {
      return deny(REASON_CONVERSION_UNAVAILABLE, "run spend + payment overflows u64 credits");
    }
    if (total > caps.maxCreditsPerRun) {
      return deny(
        REASON_OVER_RUN_CAP,
        `run spend ${spent.runSpentCredits} + payment ${credits} = ${total} credits, over the run cap ${caps.maxCreditsPerRun}`,
      );
    }
  }

  // 11. Per-window cap: same checked-add discipline.
  if (caps.maxCreditsPerWindow !== undefined) {
    const total = spent.windowSpentCredits + credits;
    if (total > U64_MAX) {
      return deny(REASON_CONVERSION_UNAVAILABLE, "window spend + payment overflows u64 credits");
    }
    if (total > caps.maxCreditsPerWindow) {
      return deny(
        REASON_OVER_WINDOW_CAP,
        `window spend ${spent.windowSpentCredits} + payment ${credits} = ${total} credits, over the window cap ${caps.maxCreditsPerWindow}`,
      );
    }
  }

  // 12. Approval threshold: within the hard caps but above the threshold.
  if (p.approval.thresholdCredits !== undefined && credits > p.approval.thresholdCredits) {
    return build(
      { kind: "approval_required", thresholdCredits: p.approval.thresholdCredits },
      REASON_APPROVAL_REQUIRED,
      `payment costs ${credits} credits, above the approval threshold ${p.approval.thresholdCredits}`,
      rule,
    );
  }

  // 13. Auto-allow.
  return build({ kind: "allow" }, REASON_ALLOWED, `payment of ${credits} credits authorized`, rule);
}
