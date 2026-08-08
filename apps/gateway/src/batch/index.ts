/** OpenAI-compatible tenant-scoped batch jobs (#698, slices 1-3). */

export { BATCH_ENDPOINTS, batchRouteModule } from "./handlers.js";
export type { BatchRouteModuleOptions, OpenAIBatch } from "./handlers.js";

export {
  DEFAULT_LEASE_SECONDS,
  DEFAULT_LINE_TIMEOUT_MS,
  DEFAULT_MAX_INPUT_BYTES,
  DEFAULT_MAX_LINES_PER_TICK,
  DEFAULT_MAX_RESPONSE_BYTES,
  OPERATION_FOR_ENDPOINT,
  runBatchTick,
  runTenantBatchTicks,
} from "./executor.js";
export type { BatchExecutorDeps, BatchTickResult } from "./executor.js";

export {
  BATCH_BUDGET_RECHECK_LINES,
  batchScopeChain,
  createBatchGovernance,
} from "./governance.js";
export type { BatchGateResult, BatchGovernance, BatchRefusal } from "./governance.js";

export {
  batchErrorLine,
  batchOutputLine,
  jsonlLines,
  parseBatchInputLine,
  renderJsonl,
} from "./jsonl.js";
export type { BatchInputLine, BatchInputLineResult, BatchLineError } from "./jsonl.js";

export {
  NATIVE_BATCH_COST_MULTIPLIER,
  NATIVE_BATCH_FAMILIES,
  cancelNativeBatch,
  downloadNativeBatchOutput,
  nativeBatchFamilyFor,
  nativeBatchStatusFrom,
  nativeBatchSupportsEndpoint,
  pollNativeBatch,
  submitNativeBatch,
  uploadNativeBatchInput,
} from "./provider-native.js";
export type {
  NativeBatchFamily,
  NativeBatchFetch,
  NativeBatchOutcome,
  NativeBatchState,
  NativeBatchStatus,
  NativeBatchSubmission,
} from "./provider-native.js";

export {
  BATCH_JOB_MESSAGE_OBJECT,
  batchJobFromWire,
  batchJobQueueFrom,
  consumeBatchJobBatch,
  enqueueBatchJob,
} from "./queue.js";
export type {
  BatchJobConsumeResult,
  BatchJobMessageBatch,
  BatchJobQueue,
  BatchJobWire,
} from "./queue.js";

export {
  DEFAULT_BATCH_SWEEP_PER_TENANT,
  batchSweepLimitFromEnv,
  sweepBatchExecution,
} from "./sweep.js";
export type { BatchSweepBindings } from "./sweep.js";
