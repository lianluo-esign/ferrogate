// Per-plugin tools view (#323): the tools one gateway plugin registers, over
// GET /admin/v1/plugins/{plugin_id}/tools. Reached from the tools catalog (an
// extension-id link) or by direct URL; the existing generic /app/plugins
// resource page is untouched.
import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { ToolsTable } from "@/components/tools/tools-table";
import { useAuth } from "@/hooks/use-auth";
import { adminGet } from "@/lib/gateway-client";

export default function PluginToolsPage() {
  const { pluginId = "" } = useParams<{ pluginId: string }>();
  const { session } = useAuth();
  const apiKey = session!.gatewayApiKey;

  const { data, isLoading, error } = useQuery({
    queryKey: ["plugin-tools", pluginId],
    queryFn: () =>
      adminGet(apiKey, "/admin/v1/plugins/{plugin_id}/tools", {
        params: { plugin_id: pluginId },
      }),
    enabled: pluginId !== "",
  });

  const tools = useMemo(() => data?.data ?? [], [data]);

  return (
    <div className="flex flex-col gap-4">
      <div>
        <Link to="/app/plugins" className="text-sm text-muted-foreground hover:underline">
          ← Plugins
        </Link>
      </div>
      <div>
        <h1 className="text-lg font-semibold">Tools for {pluginId}</h1>
        <p className="text-sm text-muted-foreground">
          Executable tools registered by this plugin, without provider secrets or
          plugin config.
        </p>
      </div>

      {error ? (
        <p className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          Failed to load plugin tools: {error.message}
        </p>
      ) : null}

      <ToolsTable tools={tools} isLoading={isLoading} />
    </div>
  );
}
