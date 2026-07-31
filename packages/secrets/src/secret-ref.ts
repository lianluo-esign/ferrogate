/**
 * A parsed secret reference — the crate's core domain model.
 *
 * Faithful port of the Rust `enum SecretRef` + `SecretRef::parse`. The three
 * supported URI schemes:
 *
 * - `env://VAR_NAME`
 * - `vault://<mount>/<path>#<field>`
 * - `cf://<store>/<name>`
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

/** A parsed secret reference. See the module docs for the supported schemes. */
export type SecretRef = EnvRef | VaultRef | CfSecretRef;

/** Human-readable rendering of a parsed reference (used in error messages). */
export function describeSecretRef(reference: SecretRef): string {
  switch (reference.kind) {
    case "env":
      return `env://${reference.name}`;
    case "vault":
      return `vault://${reference.mount}/${reference.path}#${reference.field}`;
    case "cfSecret":
      return `cf://${reference.store}/${reference.name}`;
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

  throw new Error(
    `unsupported secret reference scheme (expected env://, vault://, or cf://): ${trimmed}`,
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
