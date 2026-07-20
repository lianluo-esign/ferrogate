import type { ResourceConfig } from "@/lib/resource-config";
import { agentUpstreamsConfig } from "@/resources/agent-upstreams";
import { agentWorkflowsConfig } from "@/resources/agent-workflows";
import { auditEventsConfig } from "@/resources/audit-events";
import { billingEventsConfig } from "@/resources/billing-events";
import { managedWorkersConfig } from "@/resources/managed-workers";
import { mcpServersConfig } from "@/resources/mcp-servers";
import { modelsConfig } from "@/resources/models";
import { plansConfig } from "@/resources/plans";
import { pluginsConfig } from "@/resources/plugins";
import { projectsConfig } from "@/resources/projects";
import { promptTemplatesConfig } from "@/resources/prompt-templates";
import { providersConfig } from "@/resources/providers";
import { quotaPoliciesConfig } from "@/resources/quota-policies";
import { requestLogsConfig } from "@/resources/request-logs";
import { selfHostedWorkersConfig } from "@/resources/self-hosted-workers";
import { skillPackagesConfig } from "@/resources/skill-packages";
import { tenantAccountsConfig } from "@/resources/tenant-accounts";
import { usageReportsConfig } from "@/resources/usage-reports";
import { workspacesConfig } from "@/resources/workspaces";
// IAM completion (#321): RBAC + native api-keys generic resources. Virtual keys
// moved to a bespoke page (src/pages/virtual-keys.tsx) for lifecycle actions.
import { apiKeysConfig } from "@/resources/api-keys";
import { permissionsConfig } from "@/resources/permissions";
import { policiesConfig } from "@/resources/policies";
import { rolesConfig } from "@/resources/roles";

export interface ResourceRoute {
  path: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  config: ResourceConfig<any>;
}

export const RESOURCE_ROUTES: ResourceRoute[] = [
  { path: "/app/tenants", config: tenantAccountsConfig },
  { path: "/app/projects", config: projectsConfig },
  { path: "/app/workspaces", config: workspacesConfig },
  { path: "/app/quota-policies", config: quotaPoliciesConfig },
  { path: "/app/plans", config: plansConfig },
  { path: "/app/providers", config: providersConfig },
  { path: "/app/models", config: modelsConfig },
  { path: "/app/agent-upstreams", config: agentUpstreamsConfig },
  { path: "/app/agent-workflows", config: agentWorkflowsConfig },
  { path: "/app/skill-packages", config: skillPackagesConfig },
  { path: "/app/prompt-templates", config: promptTemplatesConfig },
  { path: "/app/plugins", config: pluginsConfig },
  { path: "/app/mcp-servers", config: mcpServersConfig },
  { path: "/app/self-hosted-workers", config: selfHostedWorkersConfig },
  { path: "/app/managed-workers", config: managedWorkersConfig },
  { path: "/app/request-logs", config: requestLogsConfig },
  { path: "/app/audit-events", config: auditEventsConfig },
  { path: "/app/usage-reports", config: usageReportsConfig },
  { path: "/app/billing-events", config: billingEventsConfig },
  // IAM completion (#321): appended so sibling agents' additions stay conflict-free.
  { path: "/app/api-keys-native", config: apiKeysConfig },
  { path: "/app/roles", config: rolesConfig },
  { path: "/app/permissions", config: permissionsConfig },
  { path: "/app/policies", config: policiesConfig },
];
