/**
 * PROVIDER-credential resolution — `api_key_var` (and the Bedrock/Vertex
 * composite halves) resolved through `@ferrogate/secrets` instead of being read
 * as a raw Worker variable.
 *
 * The rest of `src/keys` resolves INBOUND credentials (a caller's API key). This
 * module is the other direction: the OUTBOUND credential FerroGate presents to
 * an upstream provider. It lives here because both are credential material and
 * the same rule governs both — a credential that cannot be resolved must refuse
 * the request, never degrade to an empty string.
 *
 * ## What an operator may now write in the provider table
 *
 * ```jsonc
 * // GATEWAY_PROVIDERS
 * [{ "name": "anthropic", "kind": "anthropic",
 *    "base_url": "https://api.anthropic.com/v1",
 *    "api_key_var": "cf://provider-keys/anthropic-api-key" }]
 * ```
 *
 * | written value                 | resolved from                                    |
 * |-------------------------------|--------------------------------------------------|
 * | `ANTHROPIC_API_KEY`           | `env.ANTHROPIC_API_KEY` — the LEGACY bare name    |
 * | `env://ANTHROPIC_API_KEY`     | the same slot, said explicitly                    |
 * | `cf://<store>/<name>`         | the `FERROGATE_CF_SECRET_<NAME>` pre-bound slot   |
 * | `vault://<mount>/<p>#<field>` | REFUSED here — see the PORT-TODO below            |
 *
 * The bare name stays supported because every existing provider table is
 * written that way and `api_key_var` is documented as "names a Worker SECRET
 * binding"; a reference is recognised only by a `<scheme>:` prefix, which a
 * Worker binding name (a JavaScript identifier) can never carry, so no legacy
 * value can change meaning.
 *
 * ## FAIL CLOSED — the invariant this module exists to hold
 *
 * Every failure path returns `{ ok: false }`. It NEVER returns
 * `{ ok: true, value: "" }` and never returns a partially-resolved credential.
 * `buildModelCatalog` turns that into a refusal of the WHOLE catalog, so every
 * model answers `400 model_not_found` and nothing is dispatched. The failure
 * mode being excluded is the expensive one: an empty or `[object Object]`
 * credential is still a well-formed `Authorization` header, so a gateway that
 * degraded instead of refusing would send unauthenticated (or garbage-
 * authenticated) traffic to a paid upstream on every request, and the only
 * symptom would be a provider-side 401 that looks like an upstream outage.
 *
 * `detail` carries WHY when the reason is more specific than "unset"; the
 * caller appends it to its own message. It is built from binding NAMES and
 * scheme text only — no resolved value is ever put in it.
 *
 * ## PORT-TODO(P: inventory-policy-core §secrets, decision #423) — NOT CLOSED
 *
 * Two distinct limits remain, and they are not the same kind of thing:
 *
 * 1. **PLATFORM LIMIT — a DYNAMIC `cf://` name cannot be resolved.** Cloudflare
 *    Secrets Store values are WRITE-ONLY over REST (a `GET` returns metadata,
 *    never plaintext) and the only read path is a `[[secrets_store_secrets]]`
 *    binding declared at DEPLOY time, whose `get()` takes NO argument and serves
 *    exactly the one secret it was bound to. There is no
 *    `env.SECRETS.get(name)`. So `cf://<store>/<name>` resolves here **only for
 *    a name that was pre-bound**, selected at runtime by string through
 *    `FERROGATE_CF_SECRET_<NAME>`. Onboarding a new provider secret therefore
 *    requires a deploy. An unbound name yields `{ ok: false }` — it never falls
 *    back to a REST read, because no such read exists.
 *
 * 2. **NOT a platform limit — this seam is SYNCHRONOUS.** `ModelResolverFactory`
 *    is `(env) => ModelResolver`, and `src/index.ts` calls `modelsFromEnv(env)`
 *    inline inside two synchronous callbacks (`providerForModel` for the
 *    guardrail/rate-limit lanes), so the catalog cannot `await`. That excludes
 *    the two backends whose reads are asynchronous by construction:
 *
 *      - a `[[secrets_store_secrets]]` slot, whose plaintext needs
 *        `await slot.get()` (a STRING slot bound by `wrangler secret put`,
 *        `[vars]`, or a Secrets Store value injected as a var resolves fine);
 *      - `vault://`, which needs `fetch`.
 *
 *    Both are fully implemented in `@ferrogate/secrets` and both DO resolve on
 *    the asynchronous seam in `apps/mcp/src/ports.ts::workerSecretResolver`.
 *    Closing it here means making `ModelResolverFactory` async, which is an edit
 *    to `src/index.ts` — a composition root this slice does not own. Until then
 *    the closest behavior implemented is: refuse, naming the exact reason and
 *    the synchronous alternative. `test/keys/provider-secrets.test.ts` pins both
 *    refusals so the approximation cannot silently become a wrong value.
 */
import {
  CfSecretBindings,
  type EnvLike,
  isSecretsStoreBinding,
  nonEmptyEnv,
  parseSecretRef,
} from "@ferrogate/secrets";

/**
 * The outcome of resolving one provider credential.
 *
 * `ok: false` with no `detail` means the plain "named binding is unset" case —
 * the caller's own "which is not bound" wording already says everything. A
 * `detail` is present only when the reason is more specific than that.
 */
export type ProviderSecretResolution =
  | { readonly ok: true; readonly value: string }
  | { readonly ok: false; readonly detail?: string };

/**
 * Anything carrying a `<scheme>:` prefix is read as a REFERENCE, never as a
 * binding name.
 *
 * Deliberately matched on the colon alone rather than on `://`: a Worker
 * binding name is a JavaScript identifier and can never contain a colon, so
 * nothing legitimate is captured, while the typo `env:/OPENAI_KEY` (one slash)
 * is caught HERE and refused with the parser's diagnostic instead of falling
 * through to a lookup of a binding literally named `env:/OPENAI_KEY` — which
 * would report a misconfiguration as a merely-unbound variable.
 */
const SECRET_REFERENCE_PREFIX = /^[A-Za-z][A-Za-z0-9+.-]*:/;

const VAULT_DETAIL =
  "vault:// references need an HTTP round trip and the model catalog is built " +
  "synchronously (ModelResolverFactory is (env) => ModelResolver), so it cannot await " +
  "one. Bind the credential as a Worker secret and name it with env://, or resolve it " +
  "through an asynchronous seam";

function detailOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Reject a slot that is a DIFFERENT Cloudflare binding (KV, R2, D1, a DO
 * namespace, a service binding) before any reader stringifies it.
 *
 * Without this, `nonEmptyEnv`/`CfSecretBindings.lookup` reach `value.trim()` on
 * it and raise a bare `TypeError`, and a call site that formatted first would
 * put the literal text `[object Object]` into an `Authorization` header. Named
 * refusal instead.
 */
function foreignBindingDetail(name: string, slot: unknown): string | undefined {
  if (slot === undefined || typeof slot === "string") return undefined;
  if (isSecretsStoreBinding(slot)) return undefined; // handled with its own message
  return `the binding ${name} is not a secret: it is a ${typeof slot} slot (a KV/R2/D1/Durable Object/service binding), so it holds no credential value`;
}

/** Read a plain-string-or-unset slot; a Secrets Store binding throws by design. */
function readStringSlot(name: string, env: EnvLike): ProviderSecretResolution {
  const foreign = foreignBindingDetail(name, env[name]);
  if (foreign !== undefined) return { ok: false, detail: foreign };
  try {
    const value = nonEmptyEnv(name, env);
    return value === undefined ? { ok: false } : { ok: true, value };
  } catch (error) {
    // `nonEmptyEnv` throws for a `[[secrets_store_secrets]]` slot, naming the
    // async reader. That is the limit-2 refusal above, stated precisely.
    return { ok: false, detail: detailOf(error) };
  }
}

/**
 * Resolve one provider credential from the Worker `env`.
 *
 * `reference` is whatever the operator wrote in `api_key_var` /
 * `aws_secret_access_key_var` / `aws_session_token_var` /
 * `gcp_access_token_var`: a bare binding name, or an `env://` / `cf://` /
 * `vault://` secret reference.
 */
export function resolveProviderSecret(
  env: Readonly<Record<string, unknown>>,
  reference: string,
): ProviderSecretResolution {
  const raw = reference.trim();
  if (raw === "") {
    return { ok: false, detail: "the reference is empty" };
  }
  const source = env as EnvLike;

  // LEGACY: a bare binding NAME. Identical behavior to the pre-secrets read.
  if (!SECRET_REFERENCE_PREFIX.test(raw)) {
    return readStringSlot(raw, source);
  }

  let parsed: ReturnType<typeof parseSecretRef>;
  try {
    parsed = parseSecretRef(raw);
  } catch (error) {
    // A malformed or unsupported scheme is a MISCONFIGURATION, not a name:
    // falling back to `env[raw]` would let `env:/OPENAI_KEY` (one slash) look
    // up a slot that will never exist and report it as merely "unbound".
    return { ok: false, detail: detailOf(error) };
  }

  switch (parsed.kind) {
    case "env":
      return readStringSlot(parsed.name, source);

    case "cfSecret": {
      // `CfSecretBindings.lookup` applies the ambiguity guard (a non-canonical
      // name maps lossily onto a shared variable, so it REFUSES rather than
      // serve a credential the operator did not name) and throws for a slot
      // that needs `await get()`.
      try {
        const value = CfSecretBindings.new(source).lookup(parsed.name);
        return value === null ? { ok: false } : { ok: true, value };
      } catch (error) {
        return { ok: false, detail: detailOf(error) };
      }
    }

    case "vault":
      return { ok: false, detail: VAULT_DETAIL };
  }
}

/**
 * The refusal message for a credential that would not resolve.
 *
 * Kept here, next to the resolver, so every call site words it identically.
 * `field` is the provider-table column (`api_key_var`, …) and `reference` is
 * the operator's own text — both are configuration, never secret. The resolved
 * VALUE is never an input to this function.
 */
export function providerSecretRefusal(
  providerName: string,
  field: string,
  reference: string,
  resolution: { readonly ok: false; readonly detail?: string },
): string {
  const base = `provider ${providerName} names ${field} ${reference}, which is not bound`;
  return resolution.detail === undefined ? base : `${base}: ${resolution.detail}`;
}
