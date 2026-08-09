import type { ResourceConfig } from "@/lib/resource-config";
import { agentUpstreamsConfig } from "@/resources/agent-upstreams";
import { agentWorkflowsConfig } from "@/resources/agent-workflows";
// IAM completion (#321): RBAC + native api-keys generic resources. Virtual keys
// moved to a bespoke page (src/pages/virtual-keys.tsx) for lifecycle actions.
import { apiKeysConfig } from "@/resources/api-keys";
import { auditEventsConfig } from "@/resources/audit-events";
import { billingEventsConfig } from "@/resources/billing-events";
import { managedWorkersConfig } from "@/resources/managed-workers";
import { mcpServersConfig } from "@/resources/mcp-servers";
import { modelsConfig } from "@/resources/models";
import { permissionsConfig } from "@/resources/permissions";
import { plansConfig } from "@/resources/plans";
import { pluginsConfig } from "@/resources/plugins";
import { policiesConfig } from "@/resources/policies";
import { projectsConfig } from "@/resources/projects";
import { promptTemplatesConfig } from "@/resources/prompt-templates";
import { providersConfig } from "@/resources/providers";
import { quotaPoliciesConfig } from "@/resources/quota-policies";
import { requestLogsConfig } from "@/resources/request-logs";
import { rolesConfig } from "@/resources/roles";
import { RESOURCE_ROUTE_PATHS } from "@/resources/route-paths";
import { selfHostedWorkersConfig } from "@/resources/self-hosted-workers";
import { skillPackagesConfig } from "@/resources/skill-packages";
import { tenantAccountsConfig } from "@/resources/tenant-accounts";
import { usageReportsConfig } from "@/resources/usage-reports";
import { workspacesConfig } from "@/resources/workspaces";

export interface ResourceRoute {
  path: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  config: ResourceConfig<any>;
}

export const RESOURCE_ROUTES: ResourceRoute[] = [
  { path: RESOURCE_ROUTE_PATHS.tenantAccounts, config: tenantAccountsConfig },
  { path: RESOURCE_ROUTE_PATHS.projects, config: projectsConfig },
  { path: RESOURCE_ROUTE_PATHS.workspaces, config: workspacesConfig },
  { path: RESOURCE_ROUTE_PATHS.quotaPolicies, config: quotaPoliciesConfig },
  { path: RESOURCE_ROUTE_PATHS.plans, config: plansConfig },
  { path: RESOURCE_ROUTE_PATHS.providers, config: providersConfig },
  { path: RESOURCE_ROUTE_PATHS.models, config: modelsConfig },
  { path: RESOURCE_ROUTE_PATHS.agentUpstreams, config: agentUpstreamsConfig },
  { path: RESOURCE_ROUTE_PATHS.agentWorkflows, config: agentWorkflowsConfig },
  { path: RESOURCE_ROUTE_PATHS.skillPackages, config: skillPackagesConfig },
  { path: RESOURCE_ROUTE_PATHS.promptTemplates, config: promptTemplatesConfig },
  { path: RESOURCE_ROUTE_PATHS.plugins, config: pluginsConfig },
  { path: RESOURCE_ROUTE_PATHS.mcpServers, config: mcpServersConfig },
  { path: RESOURCE_ROUTE_PATHS.selfHostedWorkers, config: selfHostedWorkersConfig },
  { path: RESOURCE_ROUTE_PATHS.managedWorkers, config: managedWorkersConfig },
  { path: RESOURCE_ROUTE_PATHS.requestLogs, config: requestLogsConfig },
  { path: RESOURCE_ROUTE_PATHS.auditEvents, config: auditEventsConfig },
  { path: RESOURCE_ROUTE_PATHS.usageReports, config: usageReportsConfig },
  { path: RESOURCE_ROUTE_PATHS.billingEvents, config: billingEventsConfig },
  // IAM completion (#321): appended so sibling agents' additions stay conflict-free.
  { path: RESOURCE_ROUTE_PATHS.apiKeys, config: apiKeysConfig },
  { path: RESOURCE_ROUTE_PATHS.roles, config: rolesConfig },
  { path: RESOURCE_ROUTE_PATHS.permissions, config: permissionsConfig },
  { path: RESOURCE_ROUTE_PATHS.policies, config: policiesConfig },
];
