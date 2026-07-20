// Shared renderer for the plugin-tool listing (#323), used by both the global
// tools catalog (/admin/v1/tools) and the per-plugin tools view
// (/admin/v1/plugins/{id}/tools). Both endpoints return AdminToolList with the
// same AdminTool shape, minus provider secrets and plugin config.
import { Link } from "react-router-dom";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import type { AdminSchema } from "@/lib/gateway-client";

type AdminTool = AdminSchema<"AdminTool">;

function allowlistLabel(list: string[]): string {
  return list.length === 0 ? "any" : list.join(", ");
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
  return (
    <div className="rounded-md border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Tool</TableHead>
            <TableHead>Plugin</TableHead>
            <TableHead>Approval</TableHead>
            <TableHead>Tenants</TableHead>
            <TableHead>API keys</TableHead>
            <TableHead>Routes</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {isLoading ? (
            <TableRow>
              <TableCell colSpan={6} className="h-24 text-center">
                Loading...
              </TableCell>
            </TableRow>
          ) : tools.length === 0 ? (
            <TableRow>
              <TableCell colSpan={6} className="h-24 text-center">
                No registered tools.
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
                <TableCell className="text-xs">{allowlistLabel(tool.tenant_allowlist)}</TableCell>
                <TableCell className="text-xs">{allowlistLabel(tool.api_key_allowlist)}</TableCell>
                <TableCell className="text-xs">{allowlistLabel(tool.route_allowlist)}</TableCell>
              </TableRow>
            ))
          )}
        </TableBody>
      </Table>
    </div>
  );
}
