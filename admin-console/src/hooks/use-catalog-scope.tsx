import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { useAuth } from "@/hooks/use-auth";

/**
 * Which model-catalog a scopable resource page currently addresses (#912).
 *
 * `"tenant"` sends the session's gateway key (the default, and the only option
 * a non-superadmin ever has); `"platform"` sends the platform-operator key so
 * the request reaches the PLATFORM default catalog. The backend resolves scope
 * from WHICH credential is sent — the console never sends a `tenant_id` — so the
 * only lever the toggle pulls is which key `useCatalogApiKey` returns.
 */
export type CatalogScope = "tenant" | "platform";

interface CatalogScopeContextValue {
  scope: CatalogScope;
  setScope: (scope: CatalogScope) => void;
  /** True only when the session carries a platform-operator credential. */
  canUsePlatform: boolean;
}

const CatalogScopeContext = createContext<CatalogScopeContextValue | null>(null);

/**
 * Holds the active catalog scope for the whole console. Mounted inside
 * `AuthProvider` (see `App.tsx`) so it can read the session: `canUsePlatform`
 * tracks whether a platform-operator key is present, and the scope is FORCED
 * back to `"tenant"` the moment that access disappears (logout, or a
 * non-superadmin session), so a stale `"platform"` selection can never leak the
 * operator key after sign-out.
 */
export function CatalogScopeProvider({ children }: { children: ReactNode }) {
  const { session } = useAuth();
  const canUsePlatform = Boolean(session?.platformOperatorApiKey);
  const [scope, setScope] = useState<CatalogScope>("tenant");

  useEffect(() => {
    if (!canUsePlatform && scope !== "tenant") {
      setScope("tenant");
    }
  }, [canUsePlatform, scope]);

  const value = useMemo<CatalogScopeContextValue>(
    () => ({
      // Never expose `"platform"` while platform access is unavailable, even in
      // the render before the reset effect above runs.
      scope: canUsePlatform ? scope : "tenant",
      setScope,
      canUsePlatform,
    }),
    [scope, canUsePlatform],
  );

  return (
    <CatalogScopeContext.Provider value={value}>
      {children}
    </CatalogScopeContext.Provider>
  );
}

export function useCatalogScope(): CatalogScopeContextValue {
  const context = useContext(CatalogScopeContext);
  if (!context) {
    throw new Error("useCatalogScope must be used within a CatalogScopeProvider");
  }
  return context;
}
