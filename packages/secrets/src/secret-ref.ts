/**
 * A parsed secret reference — the crate's core domain model.
 *
 * Faithful port of the Rust `enum SecretRef` + `SecretRef::parse`. The three
 * supported URI schemes:
 *
 * - `env://VAR_NAME`
 * - `vault://<mount>/<path>#<field>`
 * - `cf://<store>/<name>`
 * - `byok://<alias>` (issue #682) — a TENANT's own credential, by alias
 *
 * The first three name a deploy-time-bound value and mean the same thing for
 * every caller. `byok://` does NOT: it is resolved against the authenticated
 * caller's tenant, which is a property of the resolver rather than of the
 * reference. See `./byok.ts`.
 */

/** A parsed `env://` reference. */
export interface EnvRef {
  readonly kind: "env";
  readonly name: string;
}
/** A parsed `vault://` reference. */
export interface VaultRef {
  readonly kind: "vault";
  readonly mount: string;
  readonly path: string;
  readonly field: string;
}
/**
 * A parsed `cf://<store>/<name>` reference. `store` is a Secrets Store id (or
 * name) and `name` is the secret's name. Values resolve from the Worker-binding
 * context first (decision #423); the REST backend is write/manage-only.
 */
export interface CfSecretRef {
  readonly kind: "cfSecret";
  readonly store: string;
  readonly name: string;
}

/**
 * A parsed `byok://<alias>` reference (issue #682) — a credential the TENANT
 * registered, selected by an alias the tenant chose.
 *
 * It carries an alias and NOTHING ELSE. There is deliberately no tenant field:
 * the tenant comes from the authenticated caller and is fixed on the resolver
 * (`./byok.ts`), so a request has no syntax with which to name another tenant's
 * scope. {@link BYOK_ALIAS_PATTERN} enforces that by construction — an alias
 * cannot contain `/`, so `byok://tenant_b/openai` does not parse at all rather
 * than parsing into something a future resolver might read as a two-part path.
 */
export interface ByokRef {
  readonly kind: "byok";
  readonly alias: string;
}

/** A parsed secret reference. See the module docs for the supported schemes. */
export type SecretRef = EnvRef | VaultRef | CfSecretRef | ByokRef;

/**
 * The BYOK alias grammar: lowercase, 1–64 chars, `a-z0-9` plus `._-`, starting
 * with an alphanumeric.
 *
 * Narrow on purpose. An alias is tenant-supplied, appears in a URI, in a request
 * header, in a D1 primary key and inside the AES-GCM additional authenticated
 * data — four contexts with four escaping stories. A grammar with no separator,
 * no whitespace, no case folding and no percent-encoding has the same meaning in
 * all four, so none of those stories can disagree. Lowercase specifically
 * because `Openai` and `openai` colliding under one case-insensitive comparison
 * but not another is precisely how an alias gets resolved to the wrong row.
 */
export const BYOK_ALIAS_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/;

/** Human-readable rendering of a parsed reference (used in error messages). */
export function describeSecretRef(reference: SecretRef): string {
  switch (reference.kind) {
    case "env":
      return `env://${reference.name}`;
    case "vault":
      return `vault://${reference.mount}/${reference.path}#${reference.field}`;
    case "cfSecret":
      return `cf://${reference.store}/${reference.name}`;
    case "byok":
      // The alias is configuration, not a credential; rendering it is what makes
      // a refusal actionable. The VALUE never appears in any message.
      return `byok://${reference.alias}`;
  }
}

/**
 * Parse a raw `secret_ref` string into a {@link SecretRef}. Throws on any
 * malformed or unsupported reference, mirroring the Rust `SecretRef::parse`
 * error taxonomy verbatim.
 */
export function parseSecretRef(raw: string): SecretRef {
  const trimmed = raw.trim();

  if (trimmed.startsWith("env://")) {
    const name = trimmed.slice("env://".length);
    if (name.length === 0) {
      throw new Error(
        "env:// secret reference requires a variable name, e.g. env://OPENAI_API_KEY",
      );
    }
    return { kind: "env", name };
  }

  if (trimmed.startsWith("vault://")) {
    const rest = trimmed.slice("vault://".length);
    const hash = rest.indexOf("#");
    if (hash < 0) {
      throw new Error(
        `vault:// secret reference requires a #field suffix, e.g. vault://secret/data/openai#api_key (got ${trimmed})`,
      );
    }
    const pathPart = rest.slice(0, hash);
    const field = rest.slice(hash + 1);
    const slash = pathPart.indexOf("/");
    if (slash < 0) {
      throw new Error(
        `vault:// secret reference requires <mount>/<path>, e.g. vault://secret/data/openai#api_key (got ${trimmed})`,
      );
    }
    const mount = pathPart.slice(0, slash);
    const path = pathPart.slice(slash + 1);
    if (mount.length === 0 || path.length === 0) {
      throw new Error(
        `vault:// secret reference requires a non-empty mount and path (got ${trimmed})`,
      );
    }
    if (field.length === 0) {
      throw new Error(
        `vault:// secret reference requires a non-empty #field (got ${trimmed})`,
      );
    }
    return { kind: "vault", mount, path, field };
  }

  if (trimmed.startsWith("cf://")) {
    const rest = trimmed.slice("cf://".length);
    const slash = rest.indexOf("/");
    if (slash < 0) {
      throw new Error(
        `cf:// secret reference requires <store>/<name>, e.g. cf://provider-keys/openai-api-key (got ${trimmed})`,
      );
    }
    const store = rest.slice(0, slash);
    const name = rest.slice(slash + 1);
    if (store.length === 0 || name.length === 0) {
      throw new Error(
        "cf:// secret reference requires a non-empty store and name, e.g. cf://provider-keys/openai-api-key",
      );
    }
    return { kind: "cfSecret", store, name };
  }

  if (trimmed.startsWith("byok://")) {
    const alias = trimmed.slice("byok://".length);
    if (!BYOK_ALIAS_PATTERN.test(alias)) {
      // One message for every rejection, and it names the grammar rather than
      // echoing back which rule was broken — `byok://tenant_b/openai` and
      // `byok://Openai` are both "not an alias", and describing the first as
      // "contains a slash" invites someone to make slashes legal.
      throw new Error(
        `byok:// secret reference requires a single alias matching ` +
          `${BYOK_ALIAS_PATTERN.source} (lowercase alphanumerics plus . _ -, no path ` +
          `separators, 1-64 chars), e.g. byok://openai-enterprise (got ${trimmed})`,
      );
    }
    return { kind: "byok", alias };
  }

  throw new Error(
    "unsupported secret reference scheme (expected env://, vault://, cf://, or byok://): " +
      trimmed,
  );
}

/** Whether `value` is a syntactically valid secret reference. */
export function isSecretRef(value: string): boolean {
  try {
    parseSecretRef(value);
    return true;
  } catch {
    return false;
  }
}
