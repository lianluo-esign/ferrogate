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
