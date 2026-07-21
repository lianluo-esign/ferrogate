import type { LucideIcon } from "lucide-react";
import {
  Bot,
  Building2,
  CreditCard,
  LayoutDashboard,
  Network,
  ShieldAlert,
  ShieldCheck,
  TerminalSquare,
} from "lucide-react";
import { APP_ROUTES } from "@/lib/app-routes";

export interface NavLeaf {
  title: string;
  url: string;
}

export interface NavRoot extends NavLeaf {
  icon: LucideIcon;
}

export interface NavGroup {
  title: string;
  icon: LucideIcon;
  items: NavLeaf[];
}

export const NAV_DASHBOARD: NavRoot = {
  title: "Dashboard",
  url: APP_ROUTES.dashboard,
  icon: LayoutDashboard,
};

export const NAV_GROUPS: NavGroup[] = [
  {
    title: "Organization",
    icon: Building2,
    items: [
      { title: "Tenant Accounts", url: "/app/tenants" },
      { title: "Projects", url: "/app/projects" },
      { title: "Workspaces", url: "/app/workspaces" },
      { title: "Plans", url: "/app/plans" },
      { title: "Quota Policies", url: "/app/quota-policies" },
      { title: "Resolved Defaults", url: APP_ROUTES.tenantResolvedDefaults },
    ],
  },
  {
    title: "Access & Policy",
    icon: ShieldCheck,
    items: [
      { title: "Virtual Keys", url: APP_ROUTES.virtualKeys },
      { title: "Gateway API Keys", url: "/app/api-keys-native" },
      { title: "Roles", url: "/app/roles" },
      { title: "Permissions", url: "/app/permissions" },
      { title: "Access Policies", url: "/app/policies" },
      { title: "Tenant Role Bindings", url: APP_ROUTES.tenantRoles },
      { title: "MCP Identities", url: APP_ROUTES.mcpIdentities },
    ],
  },
  {
    title: "Gateway Setup",
    icon: Network,
    items: [
      { title: "Providers", url: "/app/providers" },
      { title: "Models", url: "/app/models" },
      { title: "Agent Upstreams", url: "/app/agent-upstreams" },
      { title: "Agent Workflows", url: "/app/agent-workflows" },
      { title: "Skill Packages", url: "/app/skill-packages" },
      { title: "Prompt Templates", url: "/app/prompt-templates" },
      { title: "Plugins", url: "/app/plugins" },
      { title: "MCP Servers", url: "/app/mcp-servers" },
    ],
  },
  {
    title: "Agents & Tools",
    icon: Bot,
    items: [
      { title: "Agent Runs", url: APP_ROUTES.agentRuns },
      { title: "Agent Schedules", url: APP_ROUTES.agentSchedules },
      { title: "Assets", url: APP_ROUTES.assets },
      { title: "Worker Registrations", url: "/app/self-hosted-workers" },
      { title: "Managed Worker Pools", url: "/app/managed-workers" },
      { title: "Self-hosted Lifecycle", url: APP_ROUTES.selfHostedWorkerOperations },
      { title: "Self-hosted Runs", url: APP_ROUTES.selfHostedRuns },
      { title: "Managed Sessions", url: APP_ROUTES.managedWorkerSessions },
      { title: "Tools Catalog", url: APP_ROUTES.tools },
      { title: "Tool Sessions", url: APP_ROUTES.toolSessions },
    ],
  },
  {
    title: "Safety & Evidence",
    icon: ShieldAlert,
    items: [
      { title: "Tool Approvals", url: APP_ROUTES.toolApprovals },
      { title: "Guardrail Policies", url: APP_ROUTES.guardrailPolicies },
      { title: "Guardrail Evaluations", url: APP_ROUTES.guardrailEvaluations },
      { title: "Investigations", url: APP_ROUTES.investigations },
      { title: "Request Logs", url: "/app/request-logs" },
      { title: "Audit Events", url: "/app/audit-events" },
    ],
  },
  {
    title: "Billing",
    icon: CreditCard,
    items: [
      { title: "Usage Reports", url: "/app/usage-reports" },
      { title: "Billing Events", url: "/app/billing-events" },
      { title: "Wallets", url: APP_ROUTES.wallets },
      { title: "Payment Methods", url: APP_ROUTES.paymentMethods },
      { title: "Billing Dead Letters", url: APP_ROUTES.billingDeadLetters },
      { title: "Metering & Usage", url: APP_ROUTES.metering },
    ],
  },
  {
    title: "Operations",
    icon: TerminalSquare,
    items: [
      { title: "System Status", url: APP_ROUTES.operationsStatus },
      { title: "Config Reload", url: APP_ROUTES.operationsConfig },
      { title: "Graceful Drain", url: APP_ROUTES.operationsDrain },
      { title: "Gateway Config Profiles", url: APP_ROUTES.operationsGatewayConfigs },
      { title: "Provider Health", url: APP_ROUTES.operationsProviderHealth },
      { title: "Telemetry Exports", url: APP_ROUTES.operationsObservability },
      { title: "Site Domains", url: APP_ROUTES.siteDomains },
    ],
  },
];

function normalizePath(path: string): string {
  if (path === "/") return path;
  return path.replace(/\/+$/, "");
}

export function isPathActive(pathname: string, itemUrl: string): boolean {
  const path = normalizePath(pathname);
  const target = normalizePath(itemUrl);
  if (target === APP_ROUTES.dashboard) return path === target;
  return path === target || path.startsWith(`${target}/`);
}

export function findNavigationLeaf(pathname: string): NavLeaf | undefined {
  if (isPathActive(pathname, NAV_DASHBOARD.url)) return NAV_DASHBOARD;

  let bestMatch: NavLeaf | undefined;
  for (const group of NAV_GROUPS) {
    for (const item of group.items) {
      if (
        isPathActive(pathname, item.url) &&
        (!bestMatch || item.url.length > bestMatch.url.length)
      ) {
        bestMatch = item;
      }
    }
  }
  return bestMatch;
}
