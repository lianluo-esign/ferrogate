import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useI18n } from "@/i18n";
import type { AdminSchema } from "@/lib/gateway-client";
// Shared renderer for the plugin-tool listing (#323), used by both the global
// tools catalog (/admin/v1/tools) and the per-plugin tools view
// (/admin/v1/plugins/{id}/tools). Both endpoints return AdminToolList with the
// same AdminTool shape, minus provider secrets and plugin config.
import { Link } from "react-router-dom";

type AdminTool = AdminSchema<"AdminTool">;

function allowlistLabel(list: string[], anyLabel: string): string {
  return list.length === 0 ? anyLabel : list.join(", ");
}

export function ToolsTable({
  tools,
  isLoading,
  /** When true, link the extension id to its per-plugin tools view. */
  linkExtension = false,
}: {
  tools: AdminTool[];
  isLoading: boolean;
  linkExtension?: boolean;
}) {
  const { t } = useI18n();
  const anyLabel = t("component.toolsTable.any");
  return (
    <div className="rounded-md border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>{t("component.toolsTable.col.tool")}</TableHead>
            <TableHead>{t("component.toolsTable.col.plugin")}</TableHead>
            <TableHead>{t("component.toolsTable.col.approval")}</TableHead>
            <TableHead>{t("component.toolsTable.col.tenants")}</TableHead>
            <TableHead>{t("component.toolsTable.col.apiKeys")}</TableHead>
            <TableHead>{t("component.toolsTable.col.routes")}</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {isLoading ? (
            <TableRow>
              <TableCell colSpan={6} className="h-24 text-center">
                {t("common.loading")}
              </TableCell>
            </TableRow>
          ) : tools.length === 0 ? (
            <TableRow>
              <TableCell colSpan={6} className="h-24 text-center">
                {t("component.toolsTable.empty")}
              </TableCell>
            </TableRow>
          ) : (
            tools.map((tool) => (
              <TableRow key={`${tool.extension_id}/${tool.name}`} data-testid={`tool-${tool.name}`}>
                <TableCell>
                  <div className="font-medium">{tool.name}</div>
                  {tool.description ? (
                    <div className="text-xs text-muted-foreground">{tool.description}</div>
                  ) : null}
                </TableCell>
                <TableCell className="text-xs">
                  {linkExtension ? (
                    <Link
                      to={`/app/plugins/${encodeURIComponent(tool.extension_id)}/tools`}
                      className="text-primary underline"
                    >
                      {tool.extension_id}
                    </Link>
                  ) : (
                    tool.extension_id
                  )}
                </TableCell>
                <TableCell>
                  <Badge variant={tool.approval_policy === "always" ? "destructive" : "secondary"}>
                    {tool.approval_policy}
                  </Badge>
                </TableCell>
                <TableCell className="text-xs">
                  {allowlistLabel(tool.tenant_allowlist, anyLabel)}
                </TableCell>
                <TableCell className="text-xs">
                  {allowlistLabel(tool.api_key_allowlist, anyLabel)}
                </TableCell>
                <TableCell className="text-xs">
                  {allowlistLabel(tool.route_allowlist, anyLabel)}
                </TableCell>
              </TableRow>
            ))
          )}
        </TableBody>
      </Table>
    </div>
  );
}
