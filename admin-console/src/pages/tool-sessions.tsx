// Tool session inspector (#323): the audit timeline for one caller-supplied
// tool session, over GET /admin/v1/tool-sessions/{session_id} (AuditEventList).
// There is no list-all-sessions endpoint — sessions are addressed by the id the
// caller stamped on its tool invocations — so this is a lookup-by-id inspector.
import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useAuth } from "@/hooks/use-auth";
import { useI18n } from "@/i18n";
import { adminGet } from "@/lib/gateway-client";

function formatUnix(unix: number | null | undefined): string {
  if (unix === null || unix === undefined) return "-";
  return new Date(unix * 1000).toLocaleString();
}

function outcomeVariant(outcome: string): "default" | "secondary" | "destructive" | "outline" {
  const value = outcome.toLowerCase();
  if (value.includes("deny") || value.includes("fail") || value.includes("error")) {
    return "destructive";
  }
  if (value.includes("allow") || value.includes("success") || value.includes("ok")) {
    return "default";
  }
  return "secondary";
}

export default function ToolSessionsPage() {
  const { session } = useAuth();
  const { t } = useI18n();
  const apiKey = session!.gatewayApiKey;

  const [sessionInput, setSessionInput] = useState("");
  const [sessionId, setSessionId] = useState("");

  const { data, isLoading, isFetching, error } = useQuery({
    queryKey: ["tool-session", sessionId],
    queryFn: () =>
      adminGet(apiKey, "/admin/v1/tool-sessions/{session_id}", {
        params: { session_id: sessionId },
      }),
    enabled: sessionId !== "",
  });

  const events = useMemo(() => data?.data ?? [], [data]);

  function lookup() {
    const trimmed = sessionInput.trim();
    if (trimmed !== "") setSessionId(trimmed);
  }

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold">{t("page.toolSessions.title")}</h1>
        <p className="text-sm text-muted-foreground">
          {t("page.toolSessions.description")}
        </p>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium">
            {t("page.toolSessions.lookup.title")}
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-wrap items-end gap-3">
          <div className="grid gap-1.5">
            <Label htmlFor="session-input">{t("page.toolSessions.field.sessionId")}</Label>
            <Input
              id="session-input"
              value={sessionInput}
              onChange={(e) => setSessionInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && lookup()}
              // eslint-disable-next-line ferrogate/no-untranslated-literal -- example session id, not translatable copy
              placeholder="sess-abc123"
              className="w-72"
            />
          </div>
          <Button type="button" onClick={lookup} disabled={sessionInput.trim() === ""}>
            {isFetching ? t("resource.table.loading") : t("page.toolSessions.inspect")}
          </Button>
        </CardContent>
      </Card>

      {error ? (
        <p role="alert" className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {t("page.toolSessions.loadError", { session: sessionId, message: error.message })}
        </p>
      ) : null}

      {sessionId === "" ? (
        <p className="text-sm text-muted-foreground">{t("page.toolSessions.prompt")}</p>
      ) : (
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t("page.toolSessions.col.occurred")}</TableHead>
                <TableHead>{t("page.toolSessions.col.action")}</TableHead>
                <TableHead>{t("page.toolSessions.col.target")}</TableHead>
                <TableHead>{t("page.toolSessions.col.outcome")}</TableHead>
                <TableHead>{t("page.toolSessions.col.message")}</TableHead>
                <TableHead>{t("page.toolSessions.col.request")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading ? (
                <TableRow>
                  <TableCell colSpan={6} className="h-24 text-center">
                    {t("resource.table.loading")}
                  </TableCell>
                </TableRow>
              ) : events.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="h-24 text-center">
                    {t("page.toolSessions.empty")}
                  </TableCell>
                </TableRow>
              ) : (
                events.map((event) => (
                  <TableRow key={event.id} data-testid={`session-event-${event.id}`}>
                    <TableCell className="text-xs">{formatUnix(event.occurred_at_unix)}</TableCell>
                    <TableCell className="text-xs font-medium">{event.action}</TableCell>
                    <TableCell className="break-all text-xs">{event.target}</TableCell>
                    <TableCell>
                      <Badge variant={outcomeVariant(event.outcome)}>{event.outcome}</Badge>
                    </TableCell>
                    <TableCell className="max-w-64 break-all text-xs">{event.message}</TableCell>
                    <TableCell className="break-all font-mono text-xs">
                      {event.request_id}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}
