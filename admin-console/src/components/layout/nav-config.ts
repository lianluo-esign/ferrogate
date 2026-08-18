import type { TranslationKey } from "@/i18n";
import { APP_ROUTES } from "@/lib/app-routes";
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

export interface NavLeaf {
  /**
   * Typed catalog key (#348). Consumers resolve it with `t(item.titleKey)` at
   * render time so the label follows the active locale; keeping the key here
   * (not resolved text) preserves this module's zero-React, pure-data shape.
   */
  titleKey: TranslationKey;
  url: string;
}

export interface NavRoot extends NavLeaf {
  icon: LucideIcon;
}

export interface NavGroup {
  titleKey: TranslationKey;
  icon: LucideIcon;
  items: NavLeaf[];
}

export const NAV_DASHBOARD: NavRoot = {
  titleKey: "nav.dashboard",
  url: APP_ROUTES.dashboard,
  icon: LayoutDashboard,
};

export const NAV_GROUPS: NavGroup[] = [
  {
    titleKey: "nav.group.organization",
    icon: Building2,
    items: [
      { titleKey: "nav.item.tenantAccounts", url: "/app/tenants" },
      { titleKey: "nav.item.projects", url: "/app/projects" },
      { titleKey: "nav.item.workspaces", url: "/app/workspaces" },
      { titleKey: "nav.item.plans", url: "/app/plans" },
      { titleKey: "nav.item.quotaPolicies", url: "/app/quota-policies" },
      { titleKey: "nav.item.resolvedDefaults", url: APP_ROUTES.tenantResolvedDefaults },
    ],
  },
  {
    titleKey: "nav.group.accessPolicy",
    icon: ShieldCheck,
    items: [
      { titleKey: "nav.item.virtualKeys", url: APP_ROUTES.virtualKeys },
      { titleKey: "nav.item.gatewayApiKeys", url: "/app/api-keys-native" },
      { titleKey: "nav.item.roles", url: "/app/roles" },
      { titleKey: "nav.item.permissions", url: "/app/permissions" },
      { titleKey: "nav.item.accessPolicies", url: "/app/policies" },
      { titleKey: "nav.item.tenantRoleBindings", url: APP_ROUTES.tenantRoles },
      { titleKey: "nav.item.mcpIdentities", url: APP_ROUTES.mcpIdentities },
    ],
  },
  {
    titleKey: "nav.group.gatewaySetup",
    icon: Network,
    items: [
      { titleKey: "nav.item.providers", url: "/app/providers" },
      { titleKey: "nav.item.models", url: "/app/models" },
      { titleKey: "nav.item.agentUpstreams", url: "/app/agent-upstreams" },
      { titleKey: "nav.item.agentWorkflows", url: "/app/agent-workflows" },
      { titleKey: "nav.item.skillPackages", url: "/app/skill-packages" },
      { titleKey: "nav.item.promptTemplates", url: "/app/prompt-templates" },
      { titleKey: "nav.item.plugins", url: "/app/plugins" },
      { titleKey: "nav.item.mcpServers", url: "/app/mcp-servers" },
    ],
  },
  {
    titleKey: "nav.group.agentsTools",
    icon: Bot,
    items: [
      { titleKey: "nav.item.agentJobs", url: APP_ROUTES.agentJobs },
      { titleKey: "nav.item.agentRuns", url: APP_ROUTES.agentRuns },
      { titleKey: "nav.item.agentSchedules", url: APP_ROUTES.agentSchedules },
      { titleKey: "nav.item.assets", url: APP_ROUTES.assets },
      { titleKey: "nav.item.withheldAssets", url: APP_ROUTES.withheldAssets },
      { titleKey: "nav.item.workerRegistrations", url: "/app/self-hosted-workers" },
      { titleKey: "nav.item.managedWorkerPools", url: "/app/managed-workers" },
      { titleKey: "nav.item.selfHostedLifecycle", url: APP_ROUTES.selfHostedWorkerOperations },
      { titleKey: "nav.item.selfHostedRuns", url: APP_ROUTES.selfHostedRuns },
      { titleKey: "nav.item.managedSessions", url: APP_ROUTES.managedWorkerSessions },
      { titleKey: "nav.item.toolsCatalog", url: APP_ROUTES.tools },
      { titleKey: "nav.item.toolSessions", url: APP_ROUTES.toolSessions },
    ],
  },
  {
    titleKey: "nav.group.safetyEvidence",
    icon: ShieldAlert,
    items: [
      { titleKey: "nav.item.toolApprovals", url: APP_ROUTES.toolApprovals },
      { titleKey: "nav.item.guardrailPolicies", url: APP_ROUTES.guardrailPolicies },
      { titleKey: "nav.item.guardrailEvaluations", url: APP_ROUTES.guardrailEvaluations },
      { titleKey: "nav.item.investigations", url: APP_ROUTES.investigations },
      { titleKey: "nav.item.requestLogs", url: "/app/request-logs" },
      { titleKey: "nav.item.auditEvents", url: "/app/audit-events" },
    ],
  },
  {
    titleKey: "nav.group.billing",
    icon: CreditCard,
    items: [
      { titleKey: "nav.item.billingGroups", url: APP_ROUTES.billingGroups },
      { titleKey: "nav.item.usageReports", url: "/app/usage-reports" },
      { titleKey: "nav.item.billingEvents", url: "/app/billing-events" },
      { titleKey: "nav.item.wallets", url: APP_ROUTES.wallets },
      { titleKey: "nav.item.paymentMethods", url: APP_ROUTES.paymentMethods },
      { titleKey: "nav.item.billingDeadLetters", url: APP_ROUTES.billingDeadLetters },
      { titleKey: "nav.item.meteringUsage", url: APP_ROUTES.metering },
    ],
  },
  {
    titleKey: "nav.group.operations",
    icon: TerminalSquare,
    items: [
      { titleKey: "nav.item.systemStatus", url: APP_ROUTES.operationsStatus },
      { titleKey: "nav.item.configReload", url: APP_ROUTES.operationsConfig },
      { titleKey: "nav.item.gracefulDrain", url: APP_ROUTES.operationsDrain },
      { titleKey: "nav.item.gatewayConfigProfiles", url: APP_ROUTES.operationsGatewayConfigs },
      { titleKey: "nav.item.providerHealth", url: APP_ROUTES.operationsProviderHealth },
      { titleKey: "nav.item.telemetryExports", url: APP_ROUTES.operationsObservability },
      { titleKey: "nav.item.staticSites", url: APP_ROUTES.staticSites },
      { titleKey: "nav.item.siteDomains", url: APP_ROUTES.siteDomains },
      { titleKey: "nav.item.announcements", url: APP_ROUTES.announcements },
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
