import { HttpError } from "../middleware/errors.js";
import { BATCH_OPERATION_IDS, type RouteModule } from "../routes/index.js";

/** Preserve the contract/auth boundary while retiring every execution entry. */
export function retiredBatchRouteModule(): RouteModule {
  return {
    operationIds: BATCH_OPERATION_IDS,
    register(router) {
      for (const operationId of BATCH_OPERATION_IDS) {
        router.register(operationId, () => {
          throw new HttpError(410, "feature_retired", "Batch processing has been retired.");
        });
      }
    },
  };
}
