import type { LucideIcon } from "lucide-react";
import {
  Activity,
  Blocks,
  Bot,
  Boxes,
  Building2,
  CreditCard,
  FileText,
  Folder,
  Gauge,
  KeyRound,
  LayoutDashboard,
  ListTree,
  Network,
  ReceiptText,
  ScrollText,
  Server,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  TerminalSquare,
  Wrench,
} from "lucide-react";

export interface NavLeaf {
  title: string;
  url: string;
}

export interface NavGroup {
  title: string;
  icon: LucideIcon;
  items: NavLeaf[];
}

export const NAV_DASHBOARD: NavLeaf = { title: "Dashboard", url: "/app" };

export const NAV_GROUPS: NavGroup[] = [
  {
    title: "Identity & Access",
    icon: ShieldCheck,
    items: [
      { title: "Tenant accounts", url: "/app/tenants" },
      { title: "Projects", url: "/app/projects" },
      { title: "Workspaces", url: "/app/workspaces" },
      { title: "API / virtual keys", url: "/app/api-keys" },
      { title: "Quota policies", url: "/app/quota-policies" },
      { title: "Plans", url: "/app/plans" },
      { title: "Resolved tenant defaults", url: "/app/tenant-resolved-defaults" },
      // IAM completion (#321): appended contiguously to keep sibling nav edits conflict-free.
      { title: "API keys", url: "/app/api-keys-native" },
      { title: "Roles", url: "/app/roles" },
      { title: "Permissions", url: "/app/permissions" },
      { title: "Policies", url: "/app/policies" },
      { title: "Tenant role bindings", url: "/app/tenant-roles" },
    ],
  },
  {
    title: "Gateway configuration",
    icon: Network,
    items: [
      { title: "Providers", url: "/app/providers" },
      { title: "Models", url: "/app/models" },
      { title: "Agent upstreams", url: "/app/agent-upstreams" },
      { title: "Agent workflows", url: "/app/agent-workflows" },
      { title: "Skill packages", url: "/app/skill-packages" },
      { title: "Prompt templates", url: "/app/prompt-templates" },
      { title: "Plugins", url: "/app/plugins" },
      { title: "MCP servers", url: "/app/mcp-servers" },
    ],
  },
  {
    title: "Infrastructure",
    icon: Server,
    items: [
      { title: "Self-hosted workers", url: "/app/self-hosted-workers" },
      { title: "Managed workers", url: "/app/managed-workers" },
      { title: "Assets", url: "/app/assets" },
    ],
  },
  {
    title: "Governance",
    icon: ShieldAlert,
    items: [{ title: "Tool approvals", url: "/app/tool-approvals" }],
  },
  {
    title: "Observability & billing",
    icon: Gauge,
    items: [
      { title: "Request logs", url: "/app/request-logs" },
      { title: "Audit events", url: "/app/audit-events" },
      { title: "Usage reports", url: "/app/usage-reports" },
      { title: "Billing events", url: "/app/billing-events" },
    ],
  },
  {
    title: "Agent Ops",
    icon: Bot,
    items: [
      { title: "Agent runs", url: "/app/agent-runs" },
      { title: "Agent schedules", url: "/app/agent-schedules" },
    ],
  },
  {
    title: "Guardrails",
    icon: ShieldAlert,
    items: [
      { title: "Guardrail policies", url: "/app/guardrail-policies" },
      { title: "Guardrail evaluations", url: "/app/guardrail-evaluations" },
      { title: "Investigations", url: "/app/investigations" },
    ],
  },
  {
    title: "Billing Ops",
    icon: ReceiptText,
    items: [
      { title: "Wallets", url: "/app/wallets" },
      { title: "Payment methods", url: "/app/payment-methods" },
      { title: "Billing dead-letters", url: "/app/billing-dead-letters" },
      { title: "Metering & usage", url: "/app/metering" },
    ],
  },
  // Worker ops (#320): self-hosted lifecycle + runs + managed sessions.
  {
    title: "Worker ops",
    icon: Boxes,
    items: [
      { title: "Self-hosted lifecycle", url: "/app/workers/self-hosted" },
      { title: "Self-hosted runs", url: "/app/workers/self-hosted-runs" },
      { title: "Managed sessions", url: "/app/workers/managed-sessions" },
    ],
  },
  // Operations cockpit (#322): status/config-reload/drain/gateway-configs +
  // provider & observability status views.
  {
    title: "Operations",
    icon: TerminalSquare,
    items: [
      { title: "Ops status", url: "/app/ops/status" },
      { title: "Config reload", url: "/app/ops/config" },
      { title: "Graceful drain", url: "/app/ops/drain" },
      { title: "Gateway config profiles", url: "/app/ops/gateway-configs" },
      { title: "Provider & runtime health", url: "/app/ops/provider-health" },
      { title: "Observability & exports", url: "/app/ops/observability" },
    ],
  },
];

export const RESOURCE_ICONS: Record<string, LucideIcon> = {
  tenants: Building2,
  projects: Folder,
  workspaces: Boxes,
  "api-keys": KeyRound,
  "quota-policies": Gauge,
  plans: CreditCard,
  providers: Network,
  models: Sparkles,
  "agent-upstreams": Bot,
  "agent-workflows": ListTree,
  "skill-packages": Blocks,
  "prompt-templates": FileText,
  plugins: Wrench,
  "mcp-servers": Server,
  "self-hosted-workers": Server,
  "managed-workers": Server,
  "request-logs": ScrollText,
  "audit-events": Activity,
  "usage-reports": ReceiptText,
  "billing-events": CreditCard,
  dashboard: LayoutDashboard,
};
