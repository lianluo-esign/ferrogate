// EN i18n — BOOTSTRAP subset (#394). Eagerly bundled into the ENTRY chunk.
//
// This holds ONLY the always-visible chrome copy needed before (and while) the
// first lazy route resolves: the language selector, shared `common.*` labels,
// the app-shell brand/nav, the login/register (`auth.*`) pages, the worker
// reveal warnings, and the theme switcher + route-load-boundary ("Loading
// page…") + sidebar a11y strings. Everything else (dashboard/resource/page.*)
// lives in `./rest` and is code-split OUT of the entry (see catalog.ts #394).
//
// ADD A KEY HERE only if it renders as chrome before any route is mounted;
// otherwise add it to `./rest.ts`. The full type union `TranslationKey` is the
// keys of BOTH files (aggregated by `../en.ts`), so a mistyped `t()` still fails
// `tsc` and zh-CN must still cover every key regardless of which file it is in.
export const enBootstrap = {
  // Language selector (used by `../language-switcher.tsx`).
  "language.label": "Language",
  "language.change": "Change language",
  "language.current": "Language: {name}. Change language",

  // A couple of genuinely shared strings, to seed the `common.*` namespace and
  // prove interpolation/pluralization end to end.
  "common.appName": "FerroGate Admin Console",
  "common.selected": "{count} selected",

  // Shared status/state copy reused across migrated surfaces (#348).
  "common.status": "Status",
  "common.checking": "Checking",
  "common.unknown": "Unknown",
  "common.noData": "No data",
  "common.pending": "pending",
  "common.unableToLoad": "Unable to load: {message}",

  // Localized boolean/state cell labels resolved by the resource framework's
  // column render callbacks (`booleanColumn`, #385).
  "common.yes": "Yes",
  "common.no": "No",
  "common.enabled": "Enabled",
  "common.disabled": "Disabled",
  "common.working": "Working…",
  "common.tenant": "Tenant",
  "common.workspace": "Workspace",

  // Shared action / a11y labels reused by the shared primitives and vendored
  // shadcn/ui chrome (#348 final slice): copy/close/reveal buttons plus the
  // sr-only accessibility labels a screen reader announces.
  "common.copy": "Copy",
  "common.done": "Done",
  "common.cancel": "Cancel",
  "common.close": "Close",
  "common.more": "More",
  "common.loading": "Loading…",
  "common.copied": "{label} copied",
  "common.breadcrumb": "Breadcrumb",
  "common.toggleSidebar": "Toggle Sidebar",

  // Auth surfaces — login + register (#348).
  "auth.field.email": "Email",
  "auth.field.password": "Password",
  "auth.login.subtitle": "Sign in to manage your workspace",
  "auth.login.submit": "Sign in",
  "auth.login.submitting": "Signing in…",
  "auth.login.error": "Login failed",
  "auth.login.registerPrompt": "Don't have an organization yet?",
  "auth.login.registerLink": "Register",
  "auth.register.title": "Create your organization",
  "auth.register.subtitle": "Sets up a new tenant with you as the owner",
  "auth.register.orgName": "Organization name",
  "auth.register.displayName": "Your name (optional)",
  "auth.register.submit": "Create organization",
  "auth.register.submitting": "Creating…",
  "auth.register.error": "Registration failed",
  "auth.register.loginPrompt": "Already have an account?",
  "auth.register.loginLink": "Sign in",

  // App shell chrome — breadcrumb, skip link, sidebar brand, sign-out (#348).
  "shell.breadcrumb.root": "FerroGate Admin",
  "shell.skipToContent": "Skip to main content",
  "shell.brand.name": "FerroGate",
  "shell.brand.tagline": "Admin Console",
  "shell.logout": "Log out",

  // Primary navigation — sidebar group label, dashboard, section groups (#348).
  "nav.controlPlane": "Control Plane",
  "nav.dashboard": "Dashboard",
  "nav.group.organization": "Organization",
  "nav.group.accessPolicy": "Access & Policy",
  "nav.group.gatewaySetup": "Gateway Setup",
  "nav.group.agentsTools": "Agents & Tools",
  "nav.group.safetyEvidence": "Safety & Evidence",
  "nav.group.billing": "Billing",
  "nav.group.operations": "Operations",

  // Navigation destinations — one key per leaf item (#348).
  "nav.item.tenantAccounts": "Tenant Accounts",
  "nav.item.projects": "Projects",
  "nav.item.workspaces": "Workspaces",
  "nav.item.plans": "Plans",
  "nav.item.quotaPolicies": "Quota Policies",
  "nav.item.resolvedDefaults": "Resolved Defaults",
  "nav.item.virtualKeys": "Virtual Keys",
  "nav.item.gatewayApiKeys": "Gateway API Keys",
  "nav.item.roles": "Roles",
  "nav.item.permissions": "Permissions",
  "nav.item.accessPolicies": "Access Policies",
  "nav.item.tenantRoleBindings": "Tenant Role Bindings",
  "nav.item.mcpIdentities": "MCP Identities",
  "nav.item.providers": "Providers",
  "nav.item.models": "Models",
  "nav.item.agentUpstreams": "Agent Upstreams",
  "nav.item.agentWorkflows": "Agent Workflows",
  "nav.item.skillPackages": "Skill Packages",
  "nav.item.promptTemplates": "Prompt Templates",
  "nav.item.plugins": "Plugins",
  "nav.item.mcpServers": "MCP Servers",
  "nav.item.agentRuns": "Agent Runs",
  "nav.item.agentSchedules": "Agent Schedules",
  "nav.item.assets": "Assets",
  "nav.item.withheldAssets": "Withheld Assets",
  "nav.item.workerRegistrations": "Worker Registrations",
  "nav.item.managedWorkerPools": "Managed Worker Pools",
  "nav.item.selfHostedLifecycle": "Self-hosted Lifecycle",
  "nav.item.selfHostedRuns": "Self-hosted Runs",
  "nav.item.managedSessions": "Managed Sessions",
  "nav.item.toolsCatalog": "Tools Catalog",
  "nav.item.toolSessions": "Tool Sessions",
  "nav.item.toolApprovals": "Tool Approvals",
  "nav.item.guardrailPolicies": "Guardrail Policies",
  "nav.item.guardrailEvaluations": "Guardrail Evaluations",
  "nav.item.investigations": "Investigations",
  "nav.item.requestLogs": "Request Logs",
  "nav.item.auditEvents": "Audit Events",
  "nav.item.usageReports": "Usage Reports",
  "nav.item.billingEvents": "Billing Events",
  "nav.item.wallets": "Wallets",
  "nav.item.paymentMethods": "Payment Methods",
  "nav.item.billingDeadLetters": "Billing Dead Letters",
  "nav.item.meteringUsage": "Metering & Usage",
  "nav.item.systemStatus": "System Status",
  "nav.item.configReload": "Config Reload",
  "nav.item.gracefulDrain": "Graceful Drain",
  "nav.item.gatewayConfigProfiles": "Gateway Config Profiles",
  "nav.item.providerHealth": "Provider Health",
  "nav.item.telemetryExports": "Telemetry Exports",
  "nav.item.staticSites": "Static Sites",
  "nav.item.siteDomains": "Site Domains",

  // Shared Worker-ops building blocks (src/components/worker-ops/
  // worker-ops-primitives.tsx): the reported-trust badge + the
  // credential-shown-once reveal dialog, used by both self-hosted worker pages.
  "workerOps.trustBadge.reported": "reported by worker",
  "workerOps.reveal.warning": "This value will not be shown again. Store it somewhere safe.",
  "workerOps.reveal.copyFailed": "Could not copy {label}; it is shown above.",

  // Shared plugin-tool listing (src/components/tools/tools-table.tsx).
  "component.toolsTable.col.tool": "Tool",
  "component.toolsTable.col.plugin": "Plugin",
  "component.toolsTable.col.approval": "Approval",
  "component.toolsTable.col.tenants": "Tenants",
  "component.toolsTable.col.apiKeys": "API keys",
  "component.toolsTable.col.routes": "Routes",
  "component.toolsTable.empty": "No registered tools.",
  "component.toolsTable.any": "any",

  // Theme selector (src/components/theme-switcher.tsx).
  "component.themeSwitcher.light": "Light",
  "component.themeSwitcher.dark": "Dark",
  "component.themeSwitcher.system": "System",
  "component.themeSwitcher.trigger": "Theme: {theme}. Change theme",
  "component.themeSwitcher.changeTheme": "Change theme",
  "component.themeSwitcher.appearance": "Appearance",

  // Lazy-route Suspense + error boundary (src/components/route-load-boundary.tsx).
  "component.routeBoundary.loading": "Loading page…",
  "component.routeBoundary.errorTitle": "Page failed to load",
  "component.routeBoundary.errorBody":
    "The page module could not be downloaded. Check the connection and reload.",
  "component.routeBoundary.reload": "Reload page",

  // Mobile sidebar sheet accessibility copy (src/components/ui/sidebar.tsx).
  "component.sidebar.title": "Sidebar",
  "component.sidebar.description": "Displays the mobile sidebar.",
} as const;
