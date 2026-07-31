/**
 * The route registry: contract operations → Hono routes.
 *
 * Registration is a LOOP over `CONTROL_PLANE_OPERATIONS`, not 197 `app.get(...)`
 * calls. The loop is the anti-drift gate `ROUTE-MAP.md` asks for, enforced three
 * ways at module load — before a single request is served:
 *
 *  1. every group module claims a contract `group` that actually exists, and
 *     every group the contract assigns to this app has a module (no orphans in
 *     either direction);
 *  2. every operation in a group resolves to a handler, or `crudGroup` throws
 *     naming the operation id (`./resource.ts`);
 *  3. the registered set is compared against the contract set, and any
 *     difference throws listing the missing/extra operation ids.
 *
 * A new operation in `runtime-api-contract.json` therefore breaks the build
 * loudly instead of 404-ing quietly in production.
 */
import type { Hono } from "hono";
import {
  type ApiOperation,
  CONTROL_PLANE_GROUPS,
  CONTROL_PLANE_OPERATIONS,
  EXPECTED_CONTROL_PLANE_OPERATION_COUNT,
  operationsInGroup,
} from "../contract.js";
import type { ControlPlaneEnv } from "../ports.js";
import type { GroupModule, Handler } from "./resource.js";

import { adminAgentCostBurnRoutes } from "./admin_agent_cost_burn.js";
import { adminAgentScheduleRoutes } from "./admin_agent_schedule.js";
import { adminAgentUpstreamRoutes } from "./admin_agent_upstream.js";
import { adminAgentWorkflowRoutes } from "./admin_agent_workflow.js";
import { adminApiKeyRoutes } from "./admin_api_key.js";
import { adminConfigOpsRoutes } from "./admin_config_ops.js";
import { adminGatewayConfigRoutes } from "./admin_gateway_config.js";
import { adminManagedWorkerRoutes } from "./admin_managed_worker.js";
import { adminMcpServerRoutes } from "./admin_mcp_server.js";
import { adminModelRoutes } from "./admin_model.js";
import { adminOverviewRoutes } from "./admin_overview.js";
import { adminPluginRoutes } from "./admin_plugin.js";
import { adminPolicyRoutes } from "./admin_policy.js";
import { adminProviderRoutes } from "./admin_provider.js";
import { adminRequestLogRoutes } from "./admin_request_log.js";
import { adminToolRoutes } from "./admin_tool.js";
import { adminVirtualKeyRoutes } from "./admin_virtual_key.js";
import { agentRunRoutes } from "./agent_run.js";
import { billingRoutes } from "./billing.js";
import { guardrailPolicyRoutes } from "./guardrail_policy.js";
import { paymentAttemptRoutes } from "./payment_attempt.js";
import { plansRoutes } from "./plans.js";
import { promptRoutes } from "./prompt.js";
import { quotaPolicyRoutes } from "./quota_policy.js";
import { rbacRoutes } from "./rbac.js";
import { selfHostedWorkerRoutes } from "./self_hosted_worker.js";
import { siteDomainRoutes } from "./site_domain.js";
import { skillRoutes } from "./skill.js";
import { tenantHierarchyRoutes } from "./tenant_hierarchy.js";
import { walletsRoutes } from "./wallets.js";
import { x402SpendPolicyRoutes } from "./x402_spend_policy.js";

/** One module per contract group this Worker owns. */
export const GROUP_MODULES: readonly GroupModule[] = [
  adminAgentCostBurnRoutes,
  adminAgentScheduleRoutes,
  adminAgentUpstreamRoutes,
  adminAgentWorkflowRoutes,
  adminApiKeyRoutes,
  adminConfigOpsRoutes,
  adminGatewayConfigRoutes,
  adminManagedWorkerRoutes,
  adminMcpServerRoutes,
  adminModelRoutes,
  adminOverviewRoutes,
  adminPluginRoutes,
  adminPolicyRoutes,
  adminProviderRoutes,
  adminRequestLogRoutes,
  adminToolRoutes,
  adminVirtualKeyRoutes,
  agentRunRoutes,
  billingRoutes,
  guardrailPolicyRoutes,
  paymentAttemptRoutes,
  plansRoutes,
  promptRoutes,
  quotaPolicyRoutes,
  rbacRoutes,
  selfHostedWorkerRoutes,
  siteDomainRoutes,
  skillRoutes,
  tenantHierarchyRoutes,
  walletsRoutes,
  x402SpendPolicyRoutes,
];

/** `operationId → handler`, built once and validated against the contract. */
function buildHandlerTable(): ReadonlyMap<string, Handler> {
  const declaredGroups = new Set(CONTROL_PLANE_GROUPS);
  const coveredGroups = new Set<string>();
  const handlers = new Map<string, Handler>();

  for (const module of GROUP_MODULES) {
    if (!declaredGroups.has(module.group)) {
      throw new Error(
        `route module claims group ${module.group}, which the contract does not assign to apps/control-plane`,
      );
    }
    if (coveredGroups.has(module.group)) {
      throw new Error(`two route modules claim group ${module.group}`);
    }
    coveredGroups.add(module.group);

    for (const [operationId, handler] of module.build(operationsInGroup(module.group))) {
      if (handlers.has(operationId)) {
        throw new Error(`two handlers registered for operation ${operationId}`);
      }
      handlers.set(operationId, handler);
    }
  }

  const orphanGroups = [...declaredGroups].filter((group) => !coveredGroups.has(group));
  if (orphanGroups.length > 0) {
    throw new Error(`no route module for contract group(s): ${orphanGroups.sort().join(", ")}`);
  }

  const { missing, extra } = diffAgainstContract([...handlers.keys()]);
  if (missing.length > 0) {
    throw new Error(`no handler for contract operation(s): ${missing.join(", ")}`);
  }
  if (extra.length > 0) {
    throw new Error(`handler(s) for operation(s) not in the contract: ${extra.join(", ")}`);
  }
  if (handlers.size !== EXPECTED_CONTROL_PLANE_OPERATION_COUNT) {
    throw new Error(
      `expected ${EXPECTED_CONTROL_PLANE_OPERATION_COUNT} control-plane handlers, built ${handlers.size}`,
    );
  }
  return handlers;
}

/**
 * The anti-drift comparison, as a pure function so a test can drive it with a
 * synthetic handler set instead of having to edit a route module to observe the
 * failure. `missing` is the answer to "which contract operation lost its
 * route"; `extra` is the answer to the opposite drift — a handler for an
 * operation the contract no longer has. Both are sorted, because the message is
 * read by a human at the point of failure.
 */
export function diffAgainstContract(handlerIds: readonly string[]): {
  readonly missing: readonly string[];
  readonly extra: readonly string[];
} {
  const registered = new Set(handlerIds);
  const contractIds = new Set(CONTROL_PLANE_OPERATIONS.map((operation) => operation.operationId));
  return {
    missing: CONTROL_PLANE_OPERATIONS.map((operation) => operation.operationId)
      .filter((operationId) => !registered.has(operationId))
      .sort(),
    extra: [...registered].filter((operationId) => !contractIds.has(operationId)).sort(),
  };
}

const HANDLERS = buildHandlerTable();

/** `operationId → handler`, for tests and introspection. */
export function handlerTable(): ReadonlyMap<string, Handler> {
  return HANDLERS;
}

/** Every operation id this app has a live route for. */
export function registeredOperationIds(): readonly string[] {
  return [...HANDLERS.keys()];
}

/** The `(operationId, method, honoPath)` triples actually mounted on Hono. */
export interface RegisteredRoute {
  readonly operationId: string;
  readonly method: string;
  readonly honoPath: string;
  readonly group: string;
}

const REGISTERED: readonly RegisteredRoute[] = CONTROL_PLANE_OPERATIONS.map(
  (operation: ApiOperation) => ({
    operationId: operation.operationId,
    method: operation.method,
    honoPath: operation.honoPath,
    group: operation.group,
  }),
);

export function registeredRoutes(): readonly RegisteredRoute[] {
  return REGISTERED;
}

/**
 * Mount every owned operation. Hono is given the contract's own path template
 * (translated to `:param` syntax by `contract.ts`), so the router and the guard
 * agree on the shape of every route by construction.
 */
export function registerRoutes(app: Hono<ControlPlaneEnv>): void {
  for (const operation of CONTROL_PLANE_OPERATIONS) {
    const handler = HANDLERS.get(operation.operationId);
    if (handler === undefined) {
      // Unreachable: `buildHandlerTable` already threw. Kept so a future
      // refactor cannot turn a missing handler into a silent skip.
      throw new Error(`no handler for contract operation ${operation.operationId}`);
    }
    app.on(operation.method, operation.honoPath, handler);
  }
}
