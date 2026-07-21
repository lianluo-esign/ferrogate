import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { Toaster } from "@/components/ui/sonner";
import { AppShell } from "@/components/layout/app-shell";
import { ProtectedRoute } from "@/components/protected-route";
import { ResourcePage } from "@/components/resource/resource-page";
import { AuthProvider } from "@/hooks/use-auth";
import AssetsPage from "@/pages/assets";
import DashboardPage from "@/pages/dashboard";
import LoginPage from "@/pages/login";
import RegisterPage from "@/pages/register";
import TenantResolvedDefaultsPage from "@/pages/tenant-resolved-defaults";
import ToolApprovalsPage from "@/pages/tool-approvals";
import AgentRunsPage from "@/pages/agent-runs";
import AgentRunDetailPage from "@/pages/agent-run-detail";
import AgentSchedulesPage from "@/pages/agent-schedules";
import GuardrailEvaluationsPage from "@/pages/guardrail-evaluations";
import GuardrailPoliciesPage from "@/pages/guardrail-policies";
import GuardrailPolicyDetailPage from "@/pages/guardrail-policy-detail";
import InvestigationsPage from "@/pages/investigations";
import BillingWalletsPage from "@/pages/billing-wallets";
import BillingPaymentMethodsPage from "@/pages/billing-payment-methods";
import BillingDeadLettersPage from "@/pages/billing-dead-letters";
import BillingMeteringPage from "@/pages/billing-metering";
// Worker ops (#320): self-hosted lifecycle + runs + managed sessions.
import SelfHostedWorkersOpsPage from "@/pages/self-hosted-workers-ops";
import SelfHostedWorkerDetailPage from "@/pages/self-hosted-worker-detail";
import SelfHostedRunsPage from "@/pages/self-hosted-runs";
import ManagedWorkerSessionsPage from "@/pages/managed-worker-sessions";
// Operations cockpit pages (#322).
import OpsStatusPage from "@/pages/ops-status";
import OpsConfigPage from "@/pages/ops-config";
import OpsDrainPage from "@/pages/ops-drain";
import OpsGatewayConfigsPage from "@/pages/ops-gateway-configs";
import OpsProviderHealthPage from "@/pages/ops-provider-health";
import OpsObservabilityPage from "@/pages/ops-observability";
// IAM completion (#321): bespoke pages for virtual-key lifecycle + tenant roles.
import VirtualKeysPage from "@/pages/virtual-keys";
import TenantRolesPage from "@/pages/tenant-roles";
// Long-tail surfaces (#323): site domains, MCP OAuth identities, plugin tools,
// tool sessions. Appended after the IAM block to keep sibling route edits
// conflict-free.
import SiteDomainsPage from "@/pages/site-domains";
import McpIdentitiesPage from "@/pages/mcp-identities";
import ToolsCatalogPage from "@/pages/tools-catalog";
import PluginToolsPage from "@/pages/plugin-tools";
import ToolSessionsPage from "@/pages/tool-sessions";
import { APP_ROUTES } from "@/lib/app-routes";
import { RESOURCE_ROUTES } from "@/resources";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 15_000,
    },
  },
});

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AuthProvider>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route path="/register" element={<RegisterPage />} />
            <Route element={<ProtectedRoute />}>
              <Route element={<AppShell />}>
                <Route path={APP_ROUTES.dashboard} element={<DashboardPage />} />
                <Route path={APP_ROUTES.assets} element={<AssetsPage />} />
                <Route
                  path={APP_ROUTES.tenantResolvedDefaults}
                  element={<TenantResolvedDefaultsPage />}
                />
                <Route path={APP_ROUTES.toolApprovals} element={<ToolApprovalsPage />} />
                <Route path={APP_ROUTES.agentRuns} element={<AgentRunsPage />} />
                <Route path={APP_ROUTES.agentRunDetail} element={<AgentRunDetailPage />} />
                <Route path={APP_ROUTES.agentSchedules} element={<AgentSchedulesPage />} />
                <Route path={APP_ROUTES.guardrailPolicies} element={<GuardrailPoliciesPage />} />
                <Route
                  path={APP_ROUTES.guardrailPolicyDetail}
                  element={<GuardrailPolicyDetailPage />}
                />
                <Route
                  path={APP_ROUTES.guardrailEvaluations}
                  element={<GuardrailEvaluationsPage />}
                />
                <Route path={APP_ROUTES.investigations} element={<InvestigationsPage />} />
                <Route path={APP_ROUTES.wallets} element={<BillingWalletsPage />} />
                <Route
                  path={APP_ROUTES.paymentMethods}
                  element={<BillingPaymentMethodsPage />}
                />
                <Route
                  path={APP_ROUTES.billingDeadLetters}
                  element={<BillingDeadLettersPage />}
                />
                <Route path={APP_ROUTES.metering} element={<BillingMeteringPage />} />
                {/* Worker ops (#320) */}
                <Route
                  path={APP_ROUTES.selfHostedWorkerOperations}
                  element={<SelfHostedWorkersOpsPage />}
                />
                <Route
                  path={APP_ROUTES.selfHostedWorkerDetail}
                  element={<SelfHostedWorkerDetailPage />}
                />
                <Route
                  path={APP_ROUTES.selfHostedRuns}
                  element={<SelfHostedRunsPage />}
                />
                <Route
                  path={APP_ROUTES.managedWorkerSessions}
                  element={<ManagedWorkerSessionsPage />}
                />
                {/* Operations cockpit (#322). */}
                <Route path={APP_ROUTES.operationsStatus} element={<OpsStatusPage />} />
                <Route path={APP_ROUTES.operationsConfig} element={<OpsConfigPage />} />
                <Route path={APP_ROUTES.operationsDrain} element={<OpsDrainPage />} />
                <Route
                  path={APP_ROUTES.operationsGatewayConfigs}
                  element={<OpsGatewayConfigsPage />}
                />
                <Route
                  path={APP_ROUTES.operationsProviderHealth}
                  element={<OpsProviderHealthPage />}
                />
                <Route
                  path={APP_ROUTES.operationsObservability}
                  element={<OpsObservabilityPage />}
                />
                {/* IAM completion (#321) bespoke routes. */}
                <Route path={APP_ROUTES.virtualKeys} element={<VirtualKeysPage />} />
                <Route path={APP_ROUTES.tenantRoles} element={<TenantRolesPage />} />
                {/* Long-tail surfaces (#323). */}
                <Route path={APP_ROUTES.siteDomains} element={<SiteDomainsPage />} />
                <Route path={APP_ROUTES.mcpIdentities} element={<McpIdentitiesPage />} />
                <Route path={APP_ROUTES.tools} element={<ToolsCatalogPage />} />
                <Route
                  path={APP_ROUTES.pluginTools}
                  element={<PluginToolsPage />}
                />
                <Route path={APP_ROUTES.toolSessions} element={<ToolSessionsPage />} />
                {RESOURCE_ROUTES.map(({ path, config }) => (
                  <Route key={path} path={path} element={<ResourcePage config={config} />} />
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
  );
}

export default App;
