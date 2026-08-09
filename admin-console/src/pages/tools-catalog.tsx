import { ToolsTable } from "@/components/tools/tools-table";
import { useAuth } from "@/hooks/use-auth";
import { useI18n } from "@/i18n";
import { adminGet } from "@/lib/gateway-client";
import { useQuery } from "@tanstack/react-query";
// Tools catalog (#323): the global registry of executable plugin tools over
// GET /admin/v1/tools (secrets + plugin config already redacted server-side).
// Each row links its owning plugin to the per-plugin tools view.
import { useMemo } from "react";

export default function ToolsCatalogPage() {
  const { session } = useAuth();
  const { t } = useI18n();
  const apiKey = (session as NonNullable<typeof session>).gatewayApiKey;

  const { data, isLoading, error } = useQuery({
    queryKey: ["tools-catalog"],
    queryFn: () => adminGet(apiKey, "/admin/v1/tools"),
  });

  const tools = useMemo(() => data?.data ?? [], [data]);

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold">{t("page.toolsCatalog.title")}</h1>
        <p className="text-sm text-muted-foreground">{t("page.toolsCatalog.description")}</p>
      </div>

      {error ? (
        <p
          role="alert"
          className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
        >
          {t("page.toolsCatalog.loadError", { message: error.message })}
        </p>
      ) : null}

      <ToolsTable tools={tools} isLoading={isLoading} linkExtension />
    </div>
  );
}
