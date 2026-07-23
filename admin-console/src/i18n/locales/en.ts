// English message catalog — the SOURCE OF TRUTH for the console's i18n.
//
// Why this file is special:
//   * `en` is declared `as const`, so its keys become a compile-time string
//     union (`TranslationKey` in `../catalog.ts`). `t("typo.key")` then fails
//     `tsc`, not at runtime.
//   * Every other locale (see `./zh-CN.ts`) is typed `Messages`, i.e.
//     `Record<TranslationKey, string>`, so a missing OR misspelled key in a
//     translation is a type error — the "reject missing Chinese keys / key
//     drift" contract from #346 is enforced by the compiler, then re-checked
//     at runtime in `../catalog.test.ts`.
//
// Keys are flat, dot-namespaced strings (`"<namespace>.<name>"`). This keeps
// the union cheap for the type-checker and lets #348 grow route-level
// namespaces (`agents.*`, `billing.*`, ...) incrementally without re-shaping
// the catalog. Interpolation placeholders use `{name}` (see `../format.ts`).
//
// Scope note (#346): this foundation ships only the keys the i18n runtime and
// its language selector need. Page copy is migrated by #348.

export const en = {
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

  // Dashboard / operations overview (#348).
  "dashboard.title": "Operations overview",
  "dashboard.subtitle": "Live gateway posture and operator actions for {name}.",
  "dashboard.updatedAt": "Updated {time}",
  "dashboard.waitingForData": "Waiting for data",
  "dashboard.posture.title": "Gateway posture",
  "dashboard.posture.description":
    "Independent live checks; unknown data is never treated as healthy.",
  "dashboard.metric.gatewayState": "Gateway state",
  "dashboard.state.ready": "Ready",
  "dashboard.state.attention": "Attention",
  "dashboard.metric.snapshot": "Snapshot {snapshot}",
  "dashboard.metric.statusEndpoint": "Status endpoint",
  "dashboard.metric.providerHealth": "Provider health",
  "dashboard.metric.healthyEnabled": "healthy / enabled",
  "dashboard.metric.pendingApprovals": "Pending approvals",
  "dashboard.metric.humanReview": "human review required",
  "dashboard.metric.recentRequests": "Recent requests",
  "dashboard.metric.requestsUnavailable": "Request logs unavailable",
  "dashboard.metric.failuresInLatest": "{failures} failures in latest {count}",
  "dashboard.metric.latestCost": "Latest cost",
  "dashboard.metric.usageReport": "Usage report",
  "dashboard.attention.title": "Needs attention",
  "dashboard.attention.active": "{count} active",
  "dashboard.attention.empty": "No active gateway, provider, or approval alerts.",
  "dashboard.alert.statusError":
    "Gateway readiness is unknown because the status check failed.",
  "dashboard.alert.clusterNotReady": "Gateway is not ready: {reason}.",
  "dashboard.alert.providersError": "Provider health is unavailable: {message}.",
  "dashboard.alert.providersUnhealthy.one": "1 provider needs attention.",
  "dashboard.alert.providersUnhealthy.other": "{count} providers need attention.",
  "dashboard.alert.approvalsError": "Pending approvals could not be checked: {message}.",
  "dashboard.alert.approvalsPending.one": "1 tool approval is waiting for review.",
  "dashboard.alert.approvalsPending.other":
    "{count} tool approvals are waiting for review.",
  "dashboard.requests.title": "Recent requests",
  "dashboard.requests.description": "Latest retained gateway traffic and failures.",
  "dashboard.requests.viewLogs": "View logs",
  "dashboard.requests.colRequest": "Request",
  "dashboard.requests.colProviderModel": "Provider / model",
  "dashboard.requests.colStarted": "Started",
  "dashboard.requests.loading": "Loading recent requests…",
  "dashboard.requests.empty": "No retained requests yet.",
  "dashboard.requests.unmappedModel": "unmapped model",
  "dashboard.usage.title": "Usage and cost",
  "dashboard.usage.description": "Latest tenant-preferred usage rollup.",
  "dashboard.usage.viewReports": "View reports",
  "dashboard.usage.loading": "Loading usage report…",
  "dashboard.usage.empty": "No usage report is available yet.",
  "dashboard.usage.cost": "Cost",
  "dashboard.usage.requests": "Requests",
  "dashboard.usage.tokens": "Tokens",
  "dashboard.usage.errors": "Errors",
  "dashboard.usage.period": "Period",
  "dashboard.usage.latest": "Latest",

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
  "nav.item.siteDomains": "Site Domains",

  // Generated resource-CRUD framework chrome (#348). These localize the shared
  // scaffolding that renders every resource page. Resource-specific display
  // names (`config.title`, field labels, row labels) stay data-driven and are
  // interpolated as `{name}` / `{field}` / `{label}` — later slices translate
  // the per-resource catalogs, not this chrome.
  "resource.action.new": "New",
  "resource.action.create": "Create",
  "resource.action.saveChanges": "Save changes",
  "resource.action.saving": "Saving…",
  "resource.action.cancel": "Cancel",
  "resource.action.edit": "Edit",
  "resource.action.delete": "Delete",
  "resource.action.retry": "Retry",
  "resource.action.loadMore": "Load more",
  "resource.action.remove": "Remove",
  "resource.action.rowActions": "Actions for {label}",

  "resource.table.loading": "Loading…",
  "resource.table.empty": "No records yet.",
  "resource.table.unavailable": "Data unavailable.",
  "resource.table.moreDetails": "More details",
  "resource.table.actionsColumn": "Actions",

  "resource.pagination.label": "{name} pagination",
  "resource.pagination.range": "Showing {start}-{end}",
  "resource.pagination.rangeOf": "Showing {start}-{end} of {total}",
  "resource.pagination.previous": "Previous",
  "resource.pagination.next": "Next",

  "resource.dialog.createTitle": "New {name}",
  "resource.dialog.editTitle": "Edit {name}",
  "resource.dialog.deleteTitle": "Delete {name}?",
  "resource.dialog.deleteDescription": "This action cannot be undone.",

  "resource.validation.required": "{field} is required",
  "resource.validation.invalidJson": "{field} must be valid JSON",

  "resource.form.saveError": "Failed to save",
  "resource.form.selectPlaceholder": "Select...",

  "resource.list.loadError": "Failed to load {name}: {message}",

  "resource.toast.created": "{name} created",
  "resource.toast.updated": "{name} updated",
  "resource.toast.deleted": "{name} deleted",

  "resource.secret.title": "Save this secret now",
  "resource.secret.description":
    "This value will not be shown again. Store it somewhere safe.",
  "resource.secret.copyClose": "Copy & close",
  "resource.secret.copyError":
    "Could not copy to clipboard; the secret is shown above.",

  "resource.picker.selectDependencyFirst": "Select {name} first",
  "resource.picker.selectPlaceholder": "Select {label}",
  "resource.picker.dialogTitle": "Select {label}",
  "resource.picker.dialogDescription": "Search and select {label}.",
  "resource.picker.loadError": "Could not load options: {message}",
  "resource.picker.noMatches": "No matching records.",
  "resource.picker.searchPlaceholder": "Search by name or ID",
  "resource.picker.searchLabel": "Search {label}",
  "resource.picker.optionsLabel": "{label} options",
  "resource.picker.useExactId": "Use exact ID",
  "resource.picker.selectedLabel": "Selected {label}",
  "resource.picker.resolutionUnavailable": "Resolution unavailable",
  "resource.picker.unresolvedReference": "Unresolved reference",
  "resource.picker.copyValue": "Copy {value}",
  "resource.picker.copyId": "Copy ID",
  "resource.picker.removeOption": "Remove {name}",

  // Per-resource copy — routing/policy/quota group (#348). Titles, descriptions,
  // column headers, field labels/descriptions, and select-option labels for the
  // quota-policies, plugins, and policies resource configs. Resource IDs, field
  // names, option values, and example code placeholders stay data-driven.
  "resource.quotaPolicies.title": "Quota policies",
  "resource.quotaPolicies.description":
    "Rate and budget limits applied to a tenant, project, workspace, or key.",
  "resource.quotaPolicies.col.scope": "Scope",
  "resource.quotaPolicies.col.scopeId": "Scope ID",
  "resource.quotaPolicies.col.rpmLimit": "RPM limit",
  "resource.quotaPolicies.col.tpmLimit": "TPM limit",
  "resource.quotaPolicies.col.monthlyBudget": "Monthly budget (USD)",
  "resource.quotaPolicies.col.assetQuota": "Tenant asset quota (bytes)",
  "resource.quotaPolicies.col.enabled": "Enabled",
  "resource.quotaPolicies.field.scopeType": "Scope type",
  "resource.quotaPolicies.option.scopeType.tenant": "Tenant",
  "resource.quotaPolicies.option.scopeType.project": "Project",
  "resource.quotaPolicies.option.scopeType.workspace": "Workspace",
  "resource.quotaPolicies.option.scopeType.key": "Key",
  "resource.quotaPolicies.field.scopeId": "Scope ID",
  "resource.quotaPolicies.field.modelAllowlist": "Model allowlist",
  "resource.quotaPolicies.field.modelAllowlist.desc":
    "Models this scope may call; leave empty to allow all models.",
  "resource.quotaPolicies.field.rpmLimit": "Requests per minute",
  "resource.quotaPolicies.field.tpmLimit": "Tokens per minute",
  "resource.quotaPolicies.field.monthlyBudget": "Monthly budget (USD)",
  "resource.quotaPolicies.field.assetQuota": "Tenant-only asset storage quota (bytes)",
  "resource.quotaPolicies.field.assetQuota.desc": "Valid only when scope type is tenant.",
  "resource.quotaPolicies.field.enabled": "Enabled",

  "resource.plugins.title": "Plugins",
  "resource.plugins.description":
    "Request hooks, tool providers, and event sinks loaded into the gateway.",
  "resource.plugins.col.id": "ID",
  "resource.plugins.col.kind": "Kind",
  "resource.plugins.col.version": "Version",
  "resource.plugins.col.enabled": "Enabled",
  "resource.plugins.col.health": "Health",
  "resource.plugins.col.lastError": "Last error",
  "resource.plugins.field.id": "ID",
  "resource.plugins.field.kind": "Kind",
  "resource.plugins.option.kind.requestHook": "Request hook",
  "resource.plugins.option.kind.toolProvider": "Tool provider",
  "resource.plugins.option.kind.eventSink": "Event sink",
  "resource.plugins.field.version": "Version",
  "resource.plugins.field.source": "Source",
  "resource.plugins.field.order": "Order",
  "resource.plugins.field.enabled": "Enabled",
  "resource.plugins.field.approvalPolicy": "Approval policy",
  "resource.plugins.option.approvalPolicy.never": "Never",
  "resource.plugins.option.approvalPolicy.always": "Always",
  "resource.plugins.field.manifest": "Manifest (JSON)",
  "resource.plugins.field.compatibility": "Compatibility (JSON)",
  "resource.plugins.field.permissions": "Permissions (JSON)",
  "resource.plugins.field.config": "Config (JSON)",

  "resource.policies.title": "Policies",
  "resource.policies.description":
    "Allow/deny rules evaluated against callers, models and providers.",
  "resource.policies.col.name": "Name",
  "resource.policies.col.effect": "Effect",
  "resource.policies.col.enabled": "Enabled",
  "resource.policies.col.code": "Deny code",
  "resource.policies.field.name": "Name",
  "resource.policies.field.name.desc": "Immutable identifier for the rule.",
  "resource.policies.field.effect": "Effect",
  "resource.policies.option.effect.deny": "Deny",
  "resource.policies.option.effect.allow": "Allow",
  "resource.policies.field.organizationIds": "Organization IDs (comma-separated)",
  "resource.policies.field.projectIds": "Projects",
  "resource.policies.field.apiKeyIds": "API key IDs (comma-separated)",
  "resource.policies.field.models": "Models",
  "resource.policies.field.providers": "Providers",
  "resource.policies.field.code": "Deny code",
  "resource.policies.field.message": "Deny message",
  "resource.policies.field.enabled": "Enabled",
} as const;
