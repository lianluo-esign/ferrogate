/**
 * `@ferrogate/admin-sdk` — the thin TypeScript client for the FerroGate
 * Control Plane API (issue #675).
 *
 * The request/response types are GENERATED from the committed contract
 * `docs/openapi/admin-api.openapi.json`; see `./client.ts` for what is
 * hand-written and why. Regenerate with `bun run generate` from this
 * directory — `test/generated-drift.test.ts` fails if the committed types and
 * the contract have drifted apart.
 */
export {
  type AdminClient,
  type AdminClientOptions,
  type ControlPlanePrefix,
  createAdminClient,
  unwrap,
} from "./client.js";
export {
  ERROR_ENVELOPE_FIELDS,
  FerrogateApiError,
  type FerrogateApiErrorInit,
  type FerrogateErrorEnvelope,
  FerrogateTransportError,
  apiErrorFrom,
  defaultCodeForStatus,
  isFerrogateApiError,
} from "./errors.js";
/** The generated contract types — `paths`, `components`, `operations`. */
export type { components, operations, paths } from "./api-types.generated.js";
