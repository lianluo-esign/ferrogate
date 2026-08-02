import { PUBLIC_API_MAJOR } from "@ferrogate/core";
/**
 * `ferrogate-agent-runtime` — the agent execution / isolation front.
 *
 * Owns 15 of the 252 contract operations (`ROUTE-MAP.md`):
 *
 * | surface | ops | auth |
 * |---|---:|---|
 * | `POST /v1/agent-runs` | 1 | bearer `agents.invoke` |
 * | `/v1/agent-jobs/**` | 5 | bearer `agent.runs.{create,read}` |
 * | `/v1/agents/**` | 3 | bearer `agents.invoke` |
 * | `/v1/self-hosted-workers/**` | 6 | **internal** (worker plane) |
 *
 * Replaces the `agent-worker` crate's CF-native path and the
 * `workers/agent-gateway` reference. Run state lives on the {@link AgentRunState}
 * Durable Object; the self-hosted dispatch queue lives on {@link WorkerPlane}.
 *
 * The Durable Object classes are exported from here because Wrangler resolves
 * `class_name` against the entry module's exports.
 */
import { Hono } from "hono";
import { agentRoutes } from "./agents/ingress.js";
import { EXPECTED_OWNED_OPERATION_COUNT, OPERATIONS } from "./contract.js";
import { contractAuth } from "./middleware/auth.js";
import { correlation, errorHandler, notFoundHandler } from "./middleware/errors.js";
import type { AgentRuntimeEnv } from "./ports.js";
import { healthRoutes } from "./routes/health.js";
import { runRoutes } from "./runs/lifecycle.js";
import { workerRoutes } from "./workers/callbacks.js";

const app = new Hono<AgentRuntimeEnv>();

app.onError(errorHandler);
app.notFound(notFoundHandler);
app.use("*", correlation);

// --- Shared anonymous probes (`ROUTE-MAP.md`: implemented in EVERY Worker) ---
// `./routes/health.ts` carries the contract documents and the Rust readiness
// decision table; this line is the mount seam. Deleting it takes
// `test/routes/health-contract.test.ts` ("the deployed Worker serves the
// contract probes") RED — that block drives `SELF`, so it cannot be satisfied
// by the module merely existing. It must stay AHEAD of `contractAuth` and of
// the three `app.route("/", …)` groups: all three probes are `anonymous`.
app.route("/", healthRoutes);
app.get("/version", (c) =>
  c.json({ api: PUBLIC_API_MAJOR, operations: EXPECTED_OWNED_OPERATION_COUNT }),
);

/**
 * The single contract-driven guard for all 15 operations. It runs BEFORE any
 * handler, so a route cannot be served without the auth kind its contract entry
 * declares — including the tenant/worker credential split that keeps the six
 * `/v1/self-hosted-workers/*` callbacks unreachable with a tenant bearer key.
 */
app.use("/v1/*", contractAuth);

app.route("/", runRoutes);
app.route("/", agentRoutes);
app.route("/", workerRoutes);

/** The operation table, for the anti-drift test and for operators. */
export const OWNED_OPERATIONS = OPERATIONS;

export { AgentRunState } from "./runs/do.js";
export { WorkerPlane } from "./workers/plane.js";

export default app;
