import { lazy, type ComponentType, type LazyExoticComponent } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "@/components/layout/app-shell";
import { ProtectedRoute } from "@/components/protected-route";
import { RouteLoadBoundary } from "@/components/route-load-boundary";
import { AppThemeProvider } from "@/components/theme-provider";
import { Toaster } from "@/components/ui/sonner";
import { I18nProvider } from "@/i18n";
import { AuthProvider } from "@/hooks/use-auth";
import { APP_ROUTES } from "@/lib/app-routes";
import { RESOURCE_ROUTE_PATHS } from "@/resources/route-paths";

const LoginPage = lazy(() => import("@/pages/login"));
const RegisterPage = lazy(() => import("@/pages/register"));
const DashboardPage = lazy(() => import("@/pages/dashboard"));
const AssetsPage = lazy(() => import("@/pages/assets"));
const WithheldAssetsPage = lazy(() => import("@/pages/withheld-assets"));
const TenantResolvedDefaultsPage = lazy(() => import("@/pages/tenant-resolved-defaults"));
const ToolApprovalsPage = lazy(() => import("@/pages/tool-approvals"));
const AgentRunsPage = lazy(() => import("@/pages/agent-runs"));
const AgentRunDetailPage = lazy(() => import("@/pages/agent-run-detail"));
const AgentSchedulesPage = lazy(() => import("@/pages/agent-schedules"));
const GuardrailEvaluationsPage = lazy(() => import("@/pages/guardrail-evaluations"));
const GuardrailPoliciesPage = lazy(() => import("@/pages/guardrail-policies"));
const GuardrailPolicyDetailPage = lazy(() => import("@/pages/guardrail-policy-detail"));
const InvestigationsPage = lazy(() => import("@/pages/investigations"));
const BillingWalletsPage = lazy(() => import("@/pages/billing-wallets"));
const BillingPaymentMethodsPage = lazy(() => import("@/pages/billing-payment-methods"));
const BillingDeadLettersPage = lazy(() => import("@/pages/billing-dead-letters"));
const BillingMeteringPage = lazy(() => import("@/pages/billing-metering"));
const SelfHostedWorkersOpsPage = lazy(() => import("@/pages/self-hosted-workers-ops"));
const SelfHostedWorkerDetailPage = lazy(() => import("@/pages/self-hosted-worker-detail"));
const SelfHostedRunsPage = lazy(() => import("@/pages/self-hosted-runs"));
const ManagedWorkerSessionsPage = lazy(() => import("@/pages/managed-worker-sessions"));
const OpsStatusPage = lazy(() => import("@/pages/ops-status"));
const OpsConfigPage = lazy(() => import("@/pages/ops-config"));
const OpsDrainPage = lazy(() => import("@/pages/ops-drain"));
const OpsGatewayConfigsPage = lazy(() => import("@/pages/ops-gateway-configs"));
const OpsProviderHealthPage = lazy(() => import("@/pages/ops-provider-health"));
const OpsObservabilityPage = lazy(() => import("@/pages/ops-observability"));
const VirtualKeysPage = lazy(() => import("@/pages/virtual-keys"));
const TenantRolesPage = lazy(() => import("@/pages/tenant-roles"));
const SiteDomainsPage = lazy(() => import("@/pages/site-domains"));
const McpIdentitiesPage = lazy(() => import("@/pages/mcp-identities"));
const ToolsCatalogPage = lazy(() => import("@/pages/tools-catalog"));
const PluginToolsPage = lazy(() => import("@/pages/plugin-tools"));
const ToolSessionsPage = lazy(() => import("@/pages/tool-sessions"));
const ResourceRoutePage = lazy(() => import("@/pages/resource-route"));

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 15_000,
    },
  },
});

function routeElement(Component: LazyExoticComponent<ComponentType>) {
  return (
    <RouteLoadBoundary>
      <Component />
    </RouteLoadBoundary>
  );
}

function App() {
  return (
    <AppThemeProvider>
      <I18nProvider>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <AuthProvider>
            <Routes>
            <Route path="/login" element={routeElement(LoginPage)} />
            <Route path="/register" element={routeElement(RegisterPage)} />
            <Route element={<ProtectedRoute />}>
              <Route element={<AppShell />}>
                <Route path={APP_ROUTES.dashboard} element={routeElement(DashboardPage)} />
                <Route path={APP_ROUTES.assets} element={routeElement(AssetsPage)} />
                <Route
                  path={APP_ROUTES.withheldAssets}
                  element={routeElement(WithheldAssetsPage)}
                />
                <Route
                  path={APP_ROUTES.tenantResolvedDefaults}
                  element={routeElement(TenantResolvedDefaultsPage)}
                />
                <Route path={APP_ROUTES.toolApprovals} element={routeElement(ToolApprovalsPage)} />
                <Route path={APP_ROUTES.agentRuns} element={routeElement(AgentRunsPage)} />
                <Route path={APP_ROUTES.agentRunDetail} element={routeElement(AgentRunDetailPage)} />
                <Route path={APP_ROUTES.agentSchedules} element={routeElement(AgentSchedulesPage)} />
                <Route path={APP_ROUTES.guardrailPolicies} element={routeElement(GuardrailPoliciesPage)} />
                <Route
                  path={APP_ROUTES.guardrailPolicyDetail}
                  element={routeElement(GuardrailPolicyDetailPage)}
                />
                <Route
                  path={APP_ROUTES.guardrailEvaluations}
                  element={routeElement(GuardrailEvaluationsPage)}
                />
                <Route path={APP_ROUTES.investigations} element={routeElement(InvestigationsPage)} />
                <Route path={APP_ROUTES.wallets} element={routeElement(BillingWalletsPage)} />
                <Route
                  path={APP_ROUTES.paymentMethods}
                  element={routeElement(BillingPaymentMethodsPage)}
                />
                <Route
                  path={APP_ROUTES.billingDeadLetters}
                  element={routeElement(BillingDeadLettersPage)}
                />
                <Route path={APP_ROUTES.metering} element={routeElement(BillingMeteringPage)} />
                <Route
                  path={APP_ROUTES.selfHostedWorkerOperations}
                  element={routeElement(SelfHostedWorkersOpsPage)}
                />
                <Route
                  path={APP_ROUTES.selfHostedWorkerDetail}
                  element={routeElement(SelfHostedWorkerDetailPage)}
                />
                <Route path={APP_ROUTES.selfHostedRuns} element={routeElement(SelfHostedRunsPage)} />
                <Route
                  path={APP_ROUTES.managedWorkerSessions}
                  element={routeElement(ManagedWorkerSessionsPage)}
                />
                <Route path={APP_ROUTES.operationsStatus} element={routeElement(OpsStatusPage)} />
                <Route path={APP_ROUTES.operationsConfig} element={routeElement(OpsConfigPage)} />
                <Route path={APP_ROUTES.operationsDrain} element={routeElement(OpsDrainPage)} />
                <Route
                  path={APP_ROUTES.operationsGatewayConfigs}
                  element={routeElement(OpsGatewayConfigsPage)}
                />
                <Route
                  path={APP_ROUTES.operationsProviderHealth}
                  element={routeElement(OpsProviderHealthPage)}
                />
                <Route
                  path={APP_ROUTES.operationsObservability}
                  element={routeElement(OpsObservabilityPage)}
                />
                <Route path={APP_ROUTES.virtualKeys} element={routeElement(VirtualKeysPage)} />
                <Route path={APP_ROUTES.tenantRoles} element={routeElement(TenantRolesPage)} />
                <Route path={APP_ROUTES.siteDomains} element={routeElement(SiteDomainsPage)} />
                <Route path={APP_ROUTES.mcpIdentities} element={routeElement(McpIdentitiesPage)} />
                <Route path={APP_ROUTES.tools} element={routeElement(ToolsCatalogPage)} />
                <Route path={APP_ROUTES.pluginTools} element={routeElement(PluginToolsPage)} />
                <Route path={APP_ROUTES.toolSessions} element={routeElement(ToolSessionsPage)} />
                {Object.values(RESOURCE_ROUTE_PATHS).map((path) => (
                  <Route key={path} path={path} element={routeElement(ResourceRoutePage)} />
                ))}
              </Route>
            </Route>
            <Route path="/" element={<Navigate to="/app" replace />} />
            <Route path="*" element={<Navigate to="/app" replace />} />
            </Routes>
          </AuthProvider>
        </BrowserRouter>
        <Toaster />
      </QueryClientProvider>
      </I18nProvider>
    </AppThemeProvider>
  );
}

export default App;
