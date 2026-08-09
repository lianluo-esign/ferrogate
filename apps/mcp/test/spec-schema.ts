/**
 * The vendored MCP `2026-07-28` schema, loaded and applied inside workerd.
 *
 * ## Why this exists
 *
 * `test/spec-2026-07-28.test.ts` pins four changelog clauses as PROSE in its
 * docstrings and asserts behaviour against them. That is a snapshot of one
 * reader's understanding on one day: it cannot notice that the specification
 * moved, it cannot notice that the reader MISREAD, and the next person to open
 * the file cannot tell "the spec says this" from "someone believed the spec
 * said this". (It was not a hypothetical: the prose reading of minor change 5
 * enumerated five cacheable methods and did not include `server/discover`,
 * which the published schema requires `ttlMs`/`cacheScope` on. The schema found
 * that; the transcription could not have.)
 *
 * So the machine-readable artifact the MCP project publishes is committed at
 * `spec/2026-07-28/schema.json` and REAL responses are validated against it.
 * The idiom is `tools/sdk-conformance`'s: drive the counterparty's own artifact
 * rather than restate its behaviour in assertions of our own composition.
 *
 * ## The two things that make the vendored copy worth having
 *
 * **Provenance and staleness.** `spec/2026-07-28/PROVENANCE.json` records the
 * upstream repository, path, commit, git blob sha, SHA-256 and byte count.
 * {@link vendoredSchemaDigest} recomputes the digest over the bytes actually
 * loaded here, and `test/spec-2026-07-28-schema.test.ts` compares it — so
 * editing `schema.json` to make an assertion pass goes RED, offline, with no
 * network. Upstream movement is a separate axis and is checked by
 * `bun apps/mcp/spec/refresh.mjs --check`, deliberately out of the hermetic
 * suite; see that file's header for why.
 *
 * **The validation must be able to fail.** {@link expectConformsToSpec} renders
 * every schema error into the assertion message, so a red run says WHICH
 * keyword at WHICH instance location rejected the response. Its ability to go
 * red is not taken on faith: the same test file feeds it deliberately-corrupted
 * copies of each real response through {@link specValidationErrors} and asserts
 * the schema rejects them, which is what distinguishes a validator that is
 * applied from one that is merely wired up (#766).
 *
 * ## Why `@cfworker/json-schema` and not `ajv`
 *
 * Ajv compiles validators with `new Function`, which workerd forbids, so it
 * cannot run in the isolate the responses are produced in. `@cfworker/json-schema`
 * interprets the schema at runtime and is written for Workers. It is a
 * devDependency of this workspace ONLY, so nothing under `src/**` can reach it
 * and the deployed bundle never carries a JSON-Schema engine.
 */
import { type OutputUnit, Validator } from "@cfworker/json-schema";

import provenance from "../spec/2026-07-28/PROVENANCE.json";
import schemaText from "../spec/2026-07-28/schema.json?raw";

/** The parsed vendored schema. Draft 2020-12, per its own `$schema`. */
const SPEC = JSON.parse(schemaText) as {
  $schema: string;
  $defs: Record<string, unknown>;
};

/** What `spec/2026-07-28/PROVENANCE.json` claims about the bytes next to it. */
export const SPEC_PROVENANCE = provenance as {
  revision: string;
  repository: string;
  path: string;
  rawUrl: string;
  upstreamCommit: string;
  upstreamCommitDate: string;
  gitBlobSha: string;
  sha256: string;
  bytes: number;
  fetchedAt: string;
};

/** Byte length of the vendored artifact as loaded (not as recorded). */
export const VENDORED_SCHEMA_BYTES = new TextEncoder().encode(schemaText).byteLength;

/** SHA-256 of the vendored artifact as loaded, lowercase hex. */
export async function vendoredSchemaDigest(): Promise<string> {
  const bytes = new TextEncoder().encode(schemaText);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** A definition name in the vendored schema's `$defs`. */
export type SpecDefinition = string;

const validators = new Map<SpecDefinition, Validator>();

/**
 * A validator for one `$defs` entry.
 *
 * Built as a root schema that `$ref`s the definition and carries the WHOLE
 * `$defs` map, because the definitions cross-reference each other with
 * `#/$defs/...` pointers — extracting one subschema in isolation would leave
 * every reference dangling. `shortCircuit: false` so a failure reports every
 * violated keyword rather than only the first.
 */
export function specValidator(definition: SpecDefinition): Validator {
  const cached = validators.get(definition);
  if (cached) return cached;
  if (!(definition in SPEC.$defs)) {
    // A typo in a definition name would otherwise produce a validator that
    // accepts everything — a green gate checking nothing.
    throw new Error(`no such definition in the vendored MCP schema: ${definition}`);
  }
  const validator = new Validator(
    { $schema: SPEC.$schema, $ref: `#/$defs/${definition}`, $defs: SPEC.$defs },
    "2020-12",
    false,
  );
  validators.set(definition, validator);
  return validator;
}

/** Every schema error `value` produces against `definition`; empty when valid. */
export function specValidationErrors(
  definition: SpecDefinition,
  value: unknown,
): readonly OutputUnit[] {
  const output = specValidator(definition).validate(value as never);
  return output.valid ? [] : output.errors;
}

function renderErrors(errors: readonly OutputUnit[]): string {
  return (
    errors
      // The top-level `$ref` unit only ever says "a subschema had errors", which
      // is noise in front of the units that name the actual keyword.
      .filter((unit) => unit.keyword !== "$ref")
      .map((unit) => `  ${unit.instanceLocation} [${unit.keyword}] ${unit.error}`)
      .join("\n")
  );
}

/**
 * Assert that `value` validates against `definition` in the vendored schema.
 *
 * Throws with the offending instance locations and keywords, so a divergence
 * reads as "the response is wrong HERE" rather than as a bare `false`.
 */
export function expectConformsToSpec(definition: SpecDefinition, value: unknown): void {
  const errors = specValidationErrors(definition, value);
  if (errors.length === 0) return;
  throw new Error(
    `response does not conform to MCP ${SPEC_PROVENANCE.revision} #/$defs/${definition}:\n` +
      `${renderErrors(errors)}\n` +
      `(schema: ${SPEC_PROVENANCE.rawUrl} @ ${SPEC_PROVENANCE.upstreamCommit})`,
  );
}

/**
 * The `const` an error definition pins its JSON-RPC code to.
 *
 * The error definitions wrap `Error` in an `allOf` whose second branch narrows
 * `code` to a literal. Reading that literal out of the SCHEMA — rather than
 * writing `-32020` in a test — is what makes minor change 12's renumbering
 * machine-checked against `JsonRpcErrorCode` instead of against a memory of it.
 */
export function specErrorCode(definition: SpecDefinition): number {
  const entry = SPEC.$defs[definition] as {
    properties?: { error?: { allOf?: { properties?: { code?: { const?: number } } }[] } };
  };
  for (const branch of entry.properties?.error?.allOf ?? []) {
    const value = branch.properties?.code?.const;
    if (typeof value === "number") return value;
  }
  throw new Error(`${definition} pins no literal error code in the vendored schema`);
}
