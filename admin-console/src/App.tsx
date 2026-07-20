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
                <Route path="/app" element={<DashboardPage />} />
                <Route path="/app/assets" element={<AssetsPage />} />
                <Route
                  path="/app/tenant-resolved-defaults"
                  element={<TenantResolvedDefaultsPage />}
                />
                <Route path="/app/tool-approvals" element={<ToolApprovalsPage />} />
                <Route path="/app/agent-runs" element={<AgentRunsPage />} />
                <Route path="/app/agent-runs/:runId" element={<AgentRunDetailPage />} />
                <Route path="/app/agent-schedules" element={<AgentSchedulesPage />} />
                <Route path="/app/guardrail-policies" element={<GuardrailPoliciesPage />} />
                <Route
                  path="/app/guardrail-policies/:policyId"
                  element={<GuardrailPolicyDetailPage />}
                />
                <Route
                  path="/app/guardrail-evaluations"
                  element={<GuardrailEvaluationsPage />}
                />
                <Route path="/app/investigations" element={<InvestigationsPage />} />
                <Route path="/app/wallets" element={<BillingWalletsPage />} />
                <Route
                  path="/app/payment-methods"
                  element={<BillingPaymentMethodsPage />}
                />
                <Route
                  path="/app/billing-dead-letters"
                  element={<BillingDeadLettersPage />}
                />
                <Route path="/app/metering" element={<BillingMeteringPage />} />
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
