import {
  consumeOnlineEvalBatch,
  createOnlineEvalSink,
  onlineEvaluation,
} from "../../src/evals/index.js";
// Library-only evaluation tests opt in explicitly. Production has no sampler.
import { GATEWAY_MIDDLEWARE as production } from "../../src/index.js";
const split = production.findIndex((fn) => fn.name === "residencyMiddleware") + 1;
export const GATEWAY_MIDDLEWARE = [
  ...production.slice(0, split),
  onlineEvaluation(createOnlineEvalSink()),
  ...production.slice(split),
];
export const gatewayQueue = consumeOnlineEvalBatch;
