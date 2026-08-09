import { useAuth } from "@/hooks/use-auth";
import { useCatalogScope } from "@/hooks/use-catalog-scope";

/**
 * The gateway credential a platform-scopable resource page should send (#912).
 *
 * Under `"platform"` scope (only reachable by a superadmin, whose session
 * carries the operator key) it returns the platform-operator key so the request
 * addresses the platform catalog; otherwise the session's tenant gateway key.
 * The console never sends a `tenant_id`: swapping the key is the whole
 * mechanism by which the backend resolves catalog scope.
 */
export function useCatalogApiKey(): string {
  const { session } = useAuth();
  const { scope, canUsePlatform } = useCatalogScope();
  if (scope === "platform" && canUsePlatform && session?.platformOperatorApiKey) {
    return session.platformOperatorApiKey;
  }
  return (session as NonNullable<typeof session>).gatewayApiKey;
}
