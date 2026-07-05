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
  ShieldCheck,
  Sparkles,
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
    ],
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
];

export const RESOURCE_ICONS: Record<string, LucideIcon> = {
  tenants: Building2,
  projects: Folder,
  workspaces: Boxes,
  "api-keys": KeyRound,
  "quota-policies": Gauge,
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
