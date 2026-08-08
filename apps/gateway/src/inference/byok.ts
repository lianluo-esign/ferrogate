/**
 * Per-tenant BYOK on the REQUEST PATH (issue #682) — selecting a tenant's own
 * provider credential per request or per route, and substituting it for the
 * platform credential before anything is dispatched.
 *
 * Read `packages/secrets/src/byok.ts` first. It owns the alias grammar, the
 * envelope, the tenant fence and the reason the binding set stays fixed. This
 * module owns only the three request-path questions:
 *
 *  1. **Which alias?** — `x-ferrogate-byok-alias` on the request (per REQUEST),
 *     else the provider row's `byok_alias` (per ROUTE). `cf-aig-byok-alias` is
 *     accepted as a synonym because Cloudflare AI Gateway ships that header and
 *     #682 names it explicitly; a client already emitting it should not have to
 *     learn a second spelling to migrate.
 *  2. **Whose?** — the AUTHENTICATED caller's tenant, off `Caller.scope`. Never
 *     a header, never a body field, never the alias string.
 *  3. **Where does it land?** — only on candidate routes whose `provider`
 *     matches the provider the alias was REGISTERED for. A credential
 *     registered for `openai` is never presented to `anthropic`, even if the
 *     tenant asks for it on an Anthropic model.
 *
 * ## Why this is a resolver WRAPPER and not an edit to `planUpstream`
 *
 * The credential has to be in place before `adapter.buildUpstreamRequest`, which
 * bakes it into the `Authorization` header, and `planUpstream` is synchronous
 * while a BYOK lookup is a D1 read. Substituting the resolver in the per-request
 * middleware — where an `await` is already legal — puts the override in front of
 * ALL FOUR dispatching surfaces (`/v1/chat/completions`, `/v1/responses`,
 * `/v1/messages`, `/v1/embeddings`, `/v1/images`) with no change to any of them,
 * so a fifth surface added later cannot forget to apply it. That is the same
 * reason the shadow mirror is fired from one place in `handlers.ts`.
 *
 * ## Fail closed, and what "closed" means here
 *
 * An EXPLICIT request-level alias that does not resolve REFUSES THE REQUEST
 * (403 `byok_alias_not_found`). It does NOT fall back to the platform's own
 * provider credential. The tenant asked to be billed on their own agreement;
 * silently serving them on FerroGate's key would move real money, look like a
 * success from every angle, and only surface on an invoice.
 *
 * A per-ROUTE default (`byok_alias` in the provider table) that does not resolve
 * is treated the same way for the route that named it: the route keeps NO
 * credential rather than the platform one, so the request fails on that
 * candidate and the failover ladder may try another. The asymmetry is
 * deliberate — a request-level alias is a claim about THIS request and a
 * route-level alias is a claim about one route, so the blast radius of each
 * refusal matches the scope of the claim.
 *
 * ## Never logged
 *
 * Nothing here writes a credential value anywhere. Refusals carry the ALIAS and
 * the PROVIDER NAME, both of which are configuration the tenant supplied.
 */
import {
  BYOK_ALIAS_PATTERN,
  type BYOK_MASTER_KEY_ENV,
  type ByokKeyring,
  TenantByokResolver,
  type TenantCredentialStore,
  byokKeyringFromEnvAsync,
} from "@ferrogate/secrets";
import { controlDatabaseFrom } from "../control-data.js";
import {
  DurableObjectTenantDatabaseRouter,
  backfillTenantConfigurationPolicy,
  tenantProviderCredentialStoreFor,
} from "@ferrogate/storage";
import type { TenantDataNamespace } from "@ferrogate/storage/durable-objects";
import type { InferenceRejection } from "./errors.js";
import { reject } from "./errors.js";
import type { Caller, InferenceBindings, ModelResolver, PhysicalRoute } from "./ports.js";

/**
 * FerroGate's own per-request alias header.
 *
 * Prefixed `x-ferrogate-` like every other gateway control header in this tree
 * (`x-ferrogate-config`, `x-request-id`) rather than reusing the Cloudflare
 * spelling as the canonical one: the alias resolves against FerroGate's control
 * database, not against an AI Gateway BYOK store, and a header that claims
 * otherwise would mislead anyone debugging it.
 */
export const BYOK_ALIAS_HEADER = "x-ferrogate-byok-alias";

/** Accepted synonym — Cloudflare AI Gateway's spelling (named in issue #682). */
export const CF_AIG_BYOK_ALIAS_HEADER = "cf-aig-byok-alias";

/**
 * Compile-time proof that the literal in {@link byokPortsFromEnv} is the same
 * name `@ferrogate/secrets` derives key version 1 from. A rename in either place
 * is a type error here rather than a deployment that silently reports BYOK as
 * "not configured".
 */
const _BYOK_MASTER_KEY_NAME_MATCHES: typeof BYOK_MASTER_KEY_ENV = "FERROGATE_BYOK_MASTER_KEY";

/**
 * The per-request BYOK dependencies.
 *
 * `keyring` is a thunk, and async, because the fleet master key is exactly the
 * kind of value an operator SHOULD hold in Cloudflare Secrets Store — whose
 * binding is read with `await slot.get()`. Making it a thunk also means a
 * deployment with BYOK configured but never used pays nothing: the key is
 * imported only on a request that actually names an alias.
 */
export interface ByokPorts {
  readonly store: TenantCredentialStore;
  keyring(): Promise<ByokKeyring>;
}

/** Built per Worker `env`; `null` when the deployment has not enabled BYOK. */
export type ByokPortsFactory = (env: InferenceBindings) => ByokPorts | null;

/**
 * The default: the control database plus the fleet master key.
 *
 * `null` — BYOK simply off — when either is missing, rather than a throw. A
 * deployment that has not opted in must keep serving on its platform
 * credentials exactly as before; the refusals in {@link byokScopedModels} then
 * cover the only dangerous case, which is a request that ASKS for a tenant
 * credential on a deployment that cannot supply one.
 *
 * The presence check on the master key is deliberately a presence check ONLY: it
 * accepts a plain string OR a `[[secrets_store_secrets]]` binding object,
 * because the actual read happens in the async {@link ByokPorts.keyring} thunk
 * where `await slot.get()` is legal. Decoding here would exclude Secrets Store,
 * which is where this key most belongs.
 */
export function byokPortsFromEnv(env: InferenceBindings): ByokPorts | null {
  const db = controlDatabaseFrom(env);
  const namespace = (env as InferenceBindings & { readonly TENANT_DATA?: TenantDataNamespace })
    .TENANT_DATA;
  if (db === undefined || typeof db.prepare !== "function" || namespace === undefined) return null;
  // Written as a STRING LITERAL rather than `env[BYOK_MASTER_KEY_ENV]` so
  // `test/env-var-drift.test.ts`'s scanner sees a NAMED read: a dynamic index
  // would land on the "sites we cannot reason about" list, and the whole point
  // of that gate is that a deploy-time secret this Worker reads must be named
  // in `wrangler.toml` with its `wrangler secret put` instruction. The literal
  // is checked against the package constant on the line below, so the two
  // cannot drift apart silently.
  if (env["FERROGATE_BYOK_MASTER_KEY"] === undefined) return null;

  const router = new DurableObjectTenantDatabaseRouter(namespace, db);
  const store: TenantCredentialStore = {
    async lookup(tenantId, alias) {
      // The legacy table is migration input only. Once the object is available,
      // all credential reads stay in that object's database and an object error
      // is surfaced to the caller rather than falling back to CONTROL.
      await backfillTenantConfigurationPolicy(db, router, tenantId);
      const handle = await router.forTenant(tenantId);
      return tenantProviderCredentialStoreFor(handle).lookup(tenantId, alias);
    },
  };
  // Memoized per env object: the key import is cheap but not free, and the env
  // object is per request, so this caches within a request without leaking a
  // key across isolate-reused requests any longer than the env itself lives.
  let pending: Promise<ByokKeyring> | null = null;
  return {
    store,
    keyring(): Promise<ByokKeyring> {
      pending ??= byokKeyringFromEnvAsync(env as Parameters<typeof byokKeyringFromEnvAsync>[0]);
      return pending;
    },
  };
}

/**
 * The alias this request selected, or `null`.
 *
 * Validated against {@link BYOK_ALIAS_PATTERN} HERE, at the trust boundary,
 * rather than being handed to the store as-is: the alias is attacker-controlled
 * text and it reaches a SQL bind parameter, a D1 primary key and the AES-GCM
 * additional authenticated data. Rejecting non-conforming text at ingress means
 * those three never disagree about what the string means.
 *
 * A MALFORMED alias is `undefined` (distinguishable from "none given"), so the
 * caller can answer 400 rather than silently ignoring a header the client
 * believes is in force — silently ignoring it would dispatch on the platform
 * credential, which is the exact wrong-billing failure this feature prevents.
 */
export function byokAliasFromRequest(request: Request): string | null | undefined {
  const raw =
    request.headers.get(BYOK_ALIAS_HEADER) ?? request.headers.get(CF_AIG_BYOK_ALIAS_HEADER);
  if (raw === null) return null;
  const alias = raw.trim();
  if (alias === "") return null;
  return BYOK_ALIAS_PATTERN.test(alias) ? alias : undefined;
}

/** The tenant a caller is scoped to, or `null` for a platform operator. */
function tenantOf(caller: Caller): string | null {
  return caller.scope.kind === "tenant" ? caller.scope.tenantId : null;
}

/**
 * `provider name → credential value` for this request.
 *
 * A Map rather than a single value because the per-ROUTE form can name a
 * different alias per provider, and a request that fails over from `openai-us`
 * to `openai-eu` must present the right one to each.
 */
export type ByokOverrides = ReadonlyMap<string, string>;

/**
 * Resolve every alias this request needs, and return a {@link ModelResolver}
 * that serves the same routes with the tenant's credentials substituted.
 *
 * Returns the resolver unchanged (and does no I/O at all) when nothing selects
 * an alias — the overwhelmingly common case, and the reason the catalog scan
 * below runs only after the cheap header check has failed to short-circuit it.
 */
export async function byokScopedModels(
  models: ModelResolver,
  ports: ByokPorts | null,
  caller: Caller,
  request: Request,
): Promise<ModelResolver | InferenceRejection> {
  const requested = byokAliasFromRequest(request);
  if (requested === undefined) {
    return reject(
      400,
      "invalid_byok_alias",
      `the ${BYOK_ALIAS_HEADER} header must be a single alias matching ` +
        `${BYOK_ALIAS_PATTERN.source} (lowercase alphanumerics plus . _ -, no path separators)`,
    );
  }

  // Per-ROUTE defaults, collected from the catalog. Done after the header check
  // so a deployment that configures no `byok_alias` anywhere and receives no
  // header does one array scan and stops.
  const routeAliases = new Set<string>();
  if (requested === null) {
    for (const route of models.catalog()) {
      if (route.byokAlias !== undefined) routeAliases.add(route.byokAlias);
    }
    if (routeAliases.size === 0) return models;
  }

  const tenantId = tenantOf(caller);
  if (tenantId === null) {
    // A platform operator has no tenant, so there is no scope in which to
    // resolve an alias. Refusing only when one was EXPLICITLY requested keeps
    // operator traffic working on a catalog that carries route-level defaults.
    if (requested === null) return models;
    return reject(
      403,
      "byok_not_available",
      "a BYOK alias can only be resolved inside a tenant scope; this credential is not " +
        "scoped to a tenant",
    );
  }

  if (ports === null) {
    if (requested === null) return models;
    return reject(
      503,
      "byok_not_configured",
      "per-tenant BYOK is not enabled on this deployment (it needs the CONTROL_DB binding " +
        "and a FERROGATE_BYOK_MASTER_KEY)",
    );
  }

  let resolver: TenantByokResolver;
  try {
    resolver = new TenantByokResolver({
      tenantId,
      store: ports.store,
      keyring: await ports.keyring(),
    });
  } catch (error) {
    // An unbound or malformed master key. Named, never echoed — the message
    // from `@ferrogate/secrets` describes the BINDING, not any key material.
    return reject(
      503,
      "byok_not_configured",
      `per-tenant BYOK could not be initialised: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }

  const overrides = new Map<string, string>();

  if (requested !== null) {
    let binding: Awaited<ReturnType<TenantByokResolver["resolveBinding"]>>;
    try {
      binding = await resolver.resolveBinding(requested);
    } catch (error) {
      // A row that does not decrypt is NOT "not found": it means the key or the
      // row is wrong, and answering 404 would send an operator hunting for a
      // registration that exists.
      return reject(
        502,
        "byok_credential_unusable",
        `BYOK alias ${requested} is registered but could not be used: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
    if (binding === null) {
      // FAIL CLOSED. Never fall through to the platform credential.
      return reject(
        403,
        "byok_alias_not_found",
        `no BYOK credential is registered under alias ${requested} for this tenant`,
      );
    }
    overrides.set(binding.provider, binding.value);
  } else {
    for (const alias of routeAliases) {
      try {
        const binding = await resolver.resolveBinding(alias);
        // A route-level default that is absent leaves the provider WITHOUT an
        // override; `applyByokOverrides` then strips the platform credential
        // from that route rather than dispatching on it.
        if (binding !== null) overrides.set(binding.provider, binding.value);
      } catch {
        // Same treatment as absent, and deliberately not fatal: one tenant's
        // undecryptable row must not take down a request that has other
        // candidates. The route it names loses its credential below.
      }
    }
  }

  return new ByokScopedModelResolver(models, overrides, routeAliases, requested);
}

/**
 * Substitute a tenant credential onto a route.
 *
 * Three cases, and the third is the one that matters:
 *
 *  - the route's provider has an override ⇒ the tenant's credential replaces
 *    the platform one;
 *  - the route named no alias and has no override ⇒ untouched, i.e. the
 *    platform credential, which is the pre-#682 behaviour;
 *  - the route DID name an alias (or the request did) and there is no override
 *    for its provider ⇒ the credential is REMOVED. Not left as the platform
 *    key. The adapter then dispatches unauthenticated and the provider refuses,
 *    which is a loud failure; leaving the platform key would be a silent,
 *    expensive success.
 */
function applyByokOverride(
  route: PhysicalRoute,
  overrides: ByokOverrides,
  requestAlias: string | null,
): PhysicalRoute {
  const override = overrides.get(route.provider);
  if (override !== undefined) {
    return { ...route, apiKey: override };
  }
  const selected = requestAlias !== null || route.byokAlias !== undefined;
  if (!selected) return route;
  const { apiKey: _stripped, ...withoutCredential } = route;
  return withoutCredential;
}

/**
 * A {@link ModelResolver} that serves another resolver's routes with this
 * tenant's credentials substituted.
 *
 * `catalog()` is passed through UNCHANGED on purpose: it backs `GET /v1/models`,
 * which reads names and capabilities and never reads `apiKey`, so rewriting
 * every route on a listing request would be pure cost. The substitution happens
 * on the two paths that lead to a dispatch.
 */
class ByokScopedModelResolver implements ModelResolver {
  constructor(
    private readonly inner: ModelResolver,
    private readonly overrides: ByokOverrides,
    private readonly routeAliases: ReadonlySet<string>,
    private readonly requestAlias: string | null,
  ) {}

  resolve(model: string): PhysicalRoute | null {
    const route = this.inner.resolve(model);
    return route === null ? null : applyByokOverride(route, this.overrides, this.requestAlias);
  }

  catalog(): readonly PhysicalRoute[] {
    return this.inner.catalog();
  }

  candidates(model: string): readonly PhysicalRoute[] {
    const inner = this.inner.candidates?.(model) ?? [];
    return inner.map((route) => applyByokOverride(route, this.overrides, this.requestAlias));
  }

  /** Diagnostics only — never rendered to a client, never carries a value. */
  get selectedAliases(): readonly string[] {
    return this.requestAlias !== null ? [this.requestAlias] : [...this.routeAliases];
  }
}
