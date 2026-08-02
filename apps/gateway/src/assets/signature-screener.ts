/**
 * Stage (2) of Rust `screen_asset_push` — detached publisher-signature
 * verification — as a DECORATOR over whatever screener the deployment already
 * has.
 *
 * ## Why a decorator and not a branch inside `BuiltinEicarScreener`
 *
 * The Rust orchestrator runs four stages in a fixed order: content validation,
 * SIGNATURE, the cross-tenant publish approval gate, then the malware scan.
 * Stages 1 and 4 are already ported (`./ports.ts`, `./scan.ts`) and stage 3 is
 * still marked (it needs an approval-record store no migration declares). Had
 * the signature check been folded into either existing screener it would have
 * had to be folded into BOTH, since `assetScreenerFromEnv` selects between
 * them — and the two would then have drifted. As a decorator it composes with
 * whichever one is selected, in front of it, which is also the Rust ORDER:
 * a `require_signature` refusal happens before the scanner is ever consulted.
 *
 * ## What it does to the verdict
 *
 *  - it never RELAXES the inner verdict: a quarantine stays a quarantine, a
 *    rejection is returned untouched;
 *  - it can only ever ADD a refusal (`asset_signature_required`, 422 — the Rust
 *    code and status);
 *  - it records the outcome on the audit line (`signature=<label>`, replacing
 *    the inner screener's hard-coded `signature=absent`) and in the manifest
 *    (`signature: SignatureStatus`), which is the Rust `VerificationManifest`
 *    field a consuming agent reads before executing an artifact.
 */
import {
  type AssetScreener,
  type AssetScreeningRejection,
  type AssetScreeningRequest,
  type AssetScreeningVerdict,
  isScreeningRejection,
} from "./ports.js";
import {
  type PublisherKeyBindings,
  PublisherKeyRegistry,
  type SignatureStatus,
  signatureIsVerified,
  signatureStatusLabel,
  verifyAssetSignature,
} from "./signature.js";

/** Worker vars this stage reads, on top of {@link PublisherKeyBindings}. */
export interface SignaturePolicyBindings extends PublisherKeyBindings {
  /**
   * Rust `AssetSecurityContext.require_signature`. Exactly `"1"`/`"true"`
   * requires every push to carry a signature that VERIFIES; anything else
   * (including absent) labels and admits.
   */
  readonly FERROGATE_ASSET_REQUIRE_SIGNATURE?: string;
}

function requireSignatureEnabled(raw: string | undefined): boolean {
  const value = (raw ?? "").trim().toLowerCase();
  return value === "1" || value === "true";
}

/**
 * Rust's `screen_asset_push` stage (2), wrapped around `inner`.
 *
 * `keys` is a PROMISE because `crypto.subtle.importKey` is async and this
 * screener is built once per isolate at the composition root, where nothing
 * may await. It is awaited on the first push and the same registry is reused
 * thereafter — a per-request import would re-parse every publisher key on every
 * upload.
 */
export class SignatureVerifyingScreener implements AssetScreener {
  readonly #inner: AssetScreener;
  readonly #keys: Promise<PublisherKeyRegistry>;
  readonly #requireSignature: boolean;

  constructor(
    inner: AssetScreener,
    keys: PublisherKeyRegistry | Promise<PublisherKeyRegistry>,
    options: { requireSignature?: boolean } = {},
  ) {
    this.#inner = inner;
    this.#keys = Promise.resolve(keys);
    this.#requireSignature = options.requireSignature === true;
  }

  async screen(
    request: AssetScreeningRequest,
  ): Promise<AssetScreeningVerdict | AssetScreeningRejection> {
    const status: SignatureStatus =
      request.signature === undefined
        ? { status: "unsigned" }
        : await verifyAssetSignature(request.content, request.signature, await this.#keys);

    if (this.#requireSignature && !signatureIsVerified(status)) {
      // Rust `asset_signature_required`, 422, with its two message shapes: an
      // absent signature and a rejected one are different operator problems.
      return {
        status: 422,
        code: "asset_signature_required",
        message:
          status.status === "unsigned"
            ? "this tenant requires signed assets but no signature was presented"
            : // `verified` is excluded by the `!signatureIsVerified` guard
              // above, but the compiler cannot see that through the helper —
              // and an `unreachable!()` here (which is what Rust writes) would
              // be a throw inside a content gate. The empty string is
              // unreachable, not a fallback.
              `this tenant requires signed assets: ${
                status.status === "verified" ? "" : status.reason
              }`,
      };
    }

    const verdict = await this.#inner.screen(request);
    // An inner REJECTION is returned verbatim: this stage may add a refusal,
    // never subtract one.
    if (isScreeningRejection(verdict)) return verdict;

    return {
      ...verdict,
      // The inner screeners write a fixed `signature=absent`; replace only that
      // token, so the scan/approval evidence they wrote is preserved exactly.
      auditDetail: verdict.auditDetail.replace(
        /signature=\S+/,
        `signature=${signatureStatusLabel(status)}`,
      ),
      manifest: { ...verdict.manifest, signature: status },
    };
  }
}

/**
 * Compose the signature stage onto `inner` from Worker bindings, or return
 * `inner` unchanged.
 *
 * The decorator is applied when EITHER publisher keys are configured OR the
 * requirement is switched on. The second disjunct is load-bearing and
 * fail-CLOSED: an operator who sets `FERROGATE_ASSET_REQUIRE_SIGNATURE=1` and
 * forgets the keys gets every push refused with
 * `asset_signature_required`, not every push admitted unsigned.
 *
 * With neither set this returns `inner` by identity, so a deployment that never
 * asked for signature verification pays nothing and its audit lines are byte
 * for byte what they were.
 */
export function withSignatureVerification(
  inner: AssetScreener,
  env: SignaturePolicyBindings,
): AssetScreener {
  const requireSignature = requireSignatureEnabled(env.FERROGATE_ASSET_REQUIRE_SIGNATURE);
  const hasKeys =
    (env.FERROGATE_ASSET_PUBLISHER_ED25519_KEYS ?? "").trim() !== "" ||
    (env.FERROGATE_ASSET_PUBLISHER_MINISIGN_KEYS ?? "").trim() !== "";
  if (!requireSignature && !hasKeys) return inner;
  return new SignatureVerifyingScreener(inner, PublisherKeyRegistry.fromEnv(env), {
    requireSignature,
  });
}
