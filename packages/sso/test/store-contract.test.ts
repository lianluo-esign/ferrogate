import { describe } from "vitest";
import { createInMemorySsoStores } from "../src/index.js";
import { samlPendingFlowStoreContract } from "../src/store-contract.js";

/**
 * The in-memory pending-flow store must satisfy the SAME contract the durable
 * D1 store will.
 *
 * This exists because of a defect shape this repo has been bitten by: a
 * predicate with TWO implementations where the tests only ever exercise one, so
 * mutating the other leaves the suite green. `take()` single-use semantics IS
 * the SAML replay defence — if the D1 twin implements it as a read followed by
 * a delete that can interleave, replay comes back and nothing here would
 * notice.
 *
 * `samlPendingFlowStoreContract` is exported from the package so
 * `apps/control-plane` can run this identical block against its D1-backed
 * store. Running it in only one place is not enough.
 */
describe("SamlPendingFlowStore contract — in-memory reference implementation", () => {
  samlPendingFlowStoreContract(() => createInMemorySsoStores().flows);
});
