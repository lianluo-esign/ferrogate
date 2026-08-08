/**
 * The D1 SSO pending-flow store, held to `@ferrogate/sso`'s OWN exported
 * contract.
 *
 * ## The trap this closes
 *
 * `packages/sso` and `packages/identity` both prove `take`'s single-use
 * semantics — against their in-memory reference implementation. The SAML
 * assertion signature stays valid FOREVER, so single-use state is the only
 * replay defence there is; if the durable twin implements `take` as a `SELECT`
 * followed by a `DELETE`, replay comes back in production and not one test in
 * either package notices, because neither exercises D1.
 *
 * `samlPendingFlowStoreContract` is exported from the package's `src/` for
 * exactly this reason. Running the IDENTICAL block here means there is one
 * contract and two implementations, rather than two contracts.
 *
 * The mutation that proves it: change `takeSsoPendingFlow` in
 * `src/identity/adapters.ts` from
 * `DELETE … WHERE state = ? AND expires_at_unix > ? RETURNING *`
 * to a `SELECT` — "take CONSUMES" and "concurrent takes: exactly ONE wins" go
 * RED here, while `packages/sso` stays green at 110.
 */
import { env } from "cloudflare:test";
import { samlPendingFlowStoreContract } from "@ferrogate/sso/store-contract";
import { beforeAll, beforeEach, describe } from "vitest";
import { ControlPlaneIdentityRepository, samlPorts } from "../src/identity/adapters.js";
import type { ControlPlaneDeps } from "../src/ports.js";
import { applySchema, db } from "./d1.js";

/**
 * The repository over the REAL `env.DB`.
 *
 * Only `controlDatabase` is supplied: the pending-flow leg touches nothing
 * else, and handing it a half-built `ControlPlaneDeps` makes that explicit — if
 * a future edit reaches for the document store from inside `take`, this file
 * throws rather than silently passing.
 */
function store() {
  const deps = {
    controlDatabase: db(),
  } as unknown as ControlPlaneDeps;
  return samlPorts(new ControlPlaneIdentityRepository(deps)).flows;
}

beforeAll(async () => {
  await applySchema();
});

beforeEach(async () => {
  await db().prepare("DELETE FROM sso_pending_flows").run();
});

describe("the D1 SSO pending-flow store satisfies the package's own contract", () => {
  samlPendingFlowStoreContract(store);
});
