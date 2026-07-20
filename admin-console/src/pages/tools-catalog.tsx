// Tools catalog (#323): the global registry of executable plugin tools over
// GET /admin/v1/tools (secrets + plugin config already redacted server-side).
// Each row links its owning plugin to the per-plugin tools view.
import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { ToolsTable } from "@/components/tools/tools-table";
import { useAuth } from "@/hooks/use-auth";
import { adminGet } from "@/lib/gateway-client";

export default function ToolsCatalogPage() {
  const { session } = useAuth();
  const apiKey = session!.gatewayApiKey;

  const { data, isLoading, error } = useQuery({
    queryKey: ["tools-catalog"],
    queryFn: () => adminGet(apiKey, "/admin/v1/tools"),
  });

  const tools = useMemo(() => data?.data ?? [], [data]);

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold">Tools catalog</h1>
        <p className="text-sm text-muted-foreground">
          Executable tools registered by gateway plugins. Approval policy and
          allowlists govern which callers, tenants, and routes may invoke each tool.
        </p>
      </div>

      {error ? (
        <p className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          Failed to load tools: {error.message}
        </p>
      ) : null}

      <ToolsTable tools={tools} isLoading={isLoading} linkExtension />
    </div>
  );
}
