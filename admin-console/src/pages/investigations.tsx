import { useState, type FormEvent, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
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
import {
  formatUnix,
  shortFingerprint,
  verdictVariant,
  type InvestigationActionCorrelation,
} from "@/lib/guardrails";

type SelectorKind = "request_id" | "trace_id" | "agent_run_id";

const SELECTOR_KINDS: SelectorKind[] = ["request_id", "trace_id", "agent_run_id"];

function Section({
  title,
  description,
  count,
  children,
}: {
  title: string;
  description?: string;
  count?: number;
  children: ReactNode;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">
          {title}
          {count !== undefined && (
            <span className="ml-2 text-sm font-normal text-muted-foreground">({count})</span>
          )}
        </CardTitle>
        {description && <CardDescription>{description}</CardDescription>}
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
}

function IdList({ label, ids }: { label: string; ids: string[] }) {
  const { t } = useI18n();
  return (
    <li>
      <span className="text-muted-foreground">{label}:</span>{" "}
      {ids.length === 0 ? (
        t("page.investigations.none")
      ) : (
        <span className="font-mono text-xs">{ids.join(", ")}</span>
      )}
    </li>
  );
}

/** One shared-action-identity group: fingerprint -> joined evidence ids + child tree (#306/#307). */
function CorrelationGroup({ group }: { group: InvestigationActionCorrelation }) {
  const { t } = useI18n();
  const childRequests = group.child_request_ids ?? [];
  const childDispatches = group.child_dispatch_ids ?? [];
  return (
    <div className="rounded-md border p-3" data-testid="correlation-group">
      <p className="break-all font-mono text-xs">{group.action_fingerprint}</p>
      <ul className="mt-2 space-y-1 border-l pl-4 text-sm">
        <IdList
          label={t("page.investigations.label.guardrailEvaluations")}
          ids={group.guardrail_evaluation_ids}
        />
        <IdList label={t("page.investigations.label.approvals")} ids={group.approval_ids} />
        <IdList
          label={t("page.investigations.label.timelineEvents")}
          ids={group.agent_event_ids}
        />
        <IdList
          label={t("page.investigations.label.auditEvents")}
          ids={group.audit_event_ids}
        />
        {(childRequests.length > 0 || childDispatches.length > 0) && (
          <li>
            <span className="text-muted-foreground">
              {t("page.investigations.childActions")}
            </span>
            <ul className="mt-1 space-y-1 border-l pl-4">
              {childRequests.map((id) => (
                <li key={id} className="font-mono text-xs">
                  {t("page.investigations.childRequest", { id })}
                </li>
              ))}
              {childDispatches.map((id) => (
                <li key={id} className="font-mono text-xs">
                  {t("page.investigations.childDispatch", { id })}
                </li>
              ))}
            </ul>
          </li>
        )}
      </ul>
    </div>
  );
}

export default function InvestigationsPage() {
  const { session } = useAuth();
  const { t, format } = useI18n();
  const apiKey = session!.gatewayApiKey;

  const selectorLabels: Record<SelectorKind, string> = {
    request_id: t("page.investigations.selector.requestId"),
    trace_id: t("page.investigations.selector.traceId"),
    agent_run_id: t("page.investigations.selector.agentRunId"),
  };

  const [kind, setKind] = useState<SelectorKind>("request_id");
  const [value, setValue] = useState("");
  const [applied, setApplied] = useState<{ kind: SelectorKind; value: string } | null>(null);

  const { data, isLoading, error } = useQuery({
    queryKey: ["investigation", applied],
    enabled: applied !== null,
    queryFn: () => {
      const query =
        applied!.kind === "request_id"
          ? { request_id: applied!.value }
          : applied!.kind === "trace_id"
            ? { trace_id: applied!.value }
            : { agent_run_id: applied!.value };
      return adminGet(apiKey, "/admin/v1/investigations", { query });
    },
  });

  function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (value.trim() === "") return;
    setApplied({ kind, value: value.trim() });
  }

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold">{t("page.investigations.title")}</h1>
        <p className="text-sm text-muted-foreground">
          {t("page.investigations.description")}
        </p>
      </div>

      <form className="flex flex-wrap items-end gap-4 rounded-md border p-4" onSubmit={handleSubmit}>
        <div className="grid gap-2">
          <Label htmlFor="investigation-kind">{t("page.investigations.lookupBy")}</Label>
          <Select value={kind} onValueChange={(next) => setKind(next as SelectorKind)}>
            <SelectTrigger id="investigation-kind" className="w-44">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {SELECTOR_KINDS.map((option) => (
                <SelectItem key={option} value={option}>
                  {selectorLabels[option]}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="grid min-w-64 flex-1 gap-2">
          <Label htmlFor="investigation-value">{selectorLabels[kind]}</Label>
          <Input
            id="investigation-value"
            value={value}
            onChange={(event) => setValue(event.target.value)}
            // eslint-disable-next-line ferrogate/no-untranslated-literal -- example identifier tokens, not translatable copy
            placeholder="req_... / trace-... / run-..."
          />
        </div>
        <Button type="submit">{t("page.investigations.investigate")}</Button>
      </form>

      {error && (
        <p role="alert" className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {t("page.investigations.loadError", { message: error.message })}
        </p>
      )}
      {isLoading && (
        <p className="text-sm text-muted-foreground">{t("page.investigations.loading")}</p>
      )}
      {!applied && !data && (
        <p className="text-sm text-muted-foreground">{t("page.investigations.prompt")}</p>
      )}

      {data && (
        <div className="flex flex-col gap-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">{t("page.investigations.outcome")}</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-wrap items-center gap-4 text-sm">
              <Badge variant={verdictVariant(data.final_outcome)}>
                {data.final_outcome}
              </Badge>
              <span className="font-mono text-xs">{data.selector}</span>
              <span>
                <span className="text-muted-foreground">
                  {t("page.investigations.totalCost")}
                </span>{" "}
                {format.currency(data.total_cost_usd, "USD", {
                  minimumFractionDigits: 4,
                  maximumFractionDigits: 4,
                })}
              </span>
              {data.identity && (
                <span className="font-mono text-xs">
                  {t("page.investigations.identity", {
                    org: data.identity.organization_id ?? "—",
                    project: data.identity.project_id ?? "—",
                    key: data.identity.api_key_id ?? "—",
                  })}
                </span>
              )}
            </CardContent>
          </Card>

          <Section
            title={t("page.investigations.section.requests")}
            count={data.requests.length}
            description={t("page.investigations.section.requestsDescription")}
          >
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t("page.investigations.col.request")}</TableHead>
                    <TableHead>{t("page.investigations.col.route")}</TableHead>
                    <TableHead>{t("page.investigations.col.providerModel")}</TableHead>
                    <TableHead>{t("common.status")}</TableHead>
                    <TableHead>{t("page.investigations.col.error")}</TableHead>
                    <TableHead>{t("page.investigations.col.parentActionFingerprint")}</TableHead>
                    <TableHead>{t("page.investigations.col.started")}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.requests.map((request) => (
                    <TableRow key={request.request_id}>
                      <TableCell className="font-mono text-xs">{request.request_id}</TableCell>
                      <TableCell>{request.route ?? "—"}</TableCell>
                      <TableCell>
                        {request.provider ?? "—"} / {request.logical_model ?? "—"}
                      </TableCell>
                      <TableCell>{request.status_code}</TableCell>
                      <TableCell className="font-mono text-xs">
                        {request.error_code ?? "—"}
                      </TableCell>
                      <TableCell
                        className="font-mono text-xs"
                        title={request.parent_action_fingerprint ?? undefined}
                      >
                        {shortFingerprint(request.parent_action_fingerprint)}
                      </TableCell>
                      <TableCell>{formatUnix(request.started_at_unix)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </Section>

          <Section
            title={t("page.investigations.label.guardrailEvaluations")}
            count={data.guardrail_evaluations.length}
          >
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t("page.investigations.col.id")}</TableHead>
                    <TableHead>{t("page.investigations.col.policy")}</TableHead>
                    <TableHead>{t("page.investigations.col.stage")}</TableHead>
                    <TableHead>{t("page.investigations.col.verdict")}</TableHead>
                    <TableHead>{t("page.investigations.col.decision")}</TableHead>
                    <TableHead>{t("page.investigations.col.decisionReason")}</TableHead>
                    <TableHead>{t("page.investigations.col.actionFingerprint")}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.guardrail_evaluations.map((evaluation) => (
                    <TableRow key={evaluation.id}>
                      <TableCell className="font-mono text-xs">{evaluation.id}</TableCell>
                      <TableCell className="font-mono text-xs">
                        {evaluation.policy_id}@r{evaluation.policy_revision}
                      </TableCell>
                      <TableCell>{evaluation.stage}</TableCell>
                      <TableCell>
                        <Badge variant={verdictVariant(evaluation.verdict)}>
                          {evaluation.verdict} / {evaluation.action} /{" "}
                          {evaluation.enforcement_status}
                        </Badge>
                      </TableCell>
                      <TableCell>{evaluation.decision ?? "—"}</TableCell>
                      <TableCell className="font-mono text-xs">
                        {evaluation.decision_reason ?? "—"}
                      </TableCell>
                      <TableCell
                        className="font-mono text-xs"
                        title={evaluation.action_fingerprint ?? undefined}
                      >
                        {shortFingerprint(evaluation.action_fingerprint)}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </Section>

          <Section
            title={t("page.investigations.label.approvals")}
            count={data.approvals.length}
          >
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t("page.investigations.col.id")}</TableHead>
                    <TableHead>{t("page.investigations.col.tool")}</TableHead>
                    <TableHead>{t("common.status")}</TableHead>
                    <TableHead>{t("page.investigations.col.decision")}</TableHead>
                    <TableHead>{t("page.investigations.col.decisionReason")}</TableHead>
                    <TableHead>{t("page.investigations.col.actionFingerprint")}</TableHead>
                    <TableHead>{t("page.investigations.col.requested")}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.approvals.map((approval) => (
                    <TableRow key={approval.id}>
                      <TableCell className="font-mono text-xs">{approval.id}</TableCell>
                      <TableCell>{approval.tool_name}</TableCell>
                      <TableCell>{approval.status}</TableCell>
                      <TableCell>{approval.decision ?? "—"}</TableCell>
                      <TableCell className="font-mono text-xs">
                        {approval.decision_reason ?? "—"}
                      </TableCell>
                      <TableCell
                        className="font-mono text-xs"
                        title={approval.action_fingerprint ?? undefined}
                      >
                        {shortFingerprint(approval.action_fingerprint)}
                      </TableCell>
                      <TableCell>{formatUnix(approval.requested_at_unix)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </Section>

          <Section
            title={t("page.investigations.section.timeline")}
            count={data.agent_events.length}
            description={t("page.investigations.section.timelineDescription", {
              count: data.agent_runs.length,
            })}
          >
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t("page.investigations.col.turn")}</TableHead>
                    <TableHead>{t("page.investigations.col.kind")}</TableHead>
                    <TableHead>{t("page.investigations.col.target")}</TableHead>
                    <TableHead>{t("page.investigations.col.outcome")}</TableHead>
                    <TableHead>{t("page.investigations.col.decision")}</TableHead>
                    <TableHead>{t("page.investigations.col.actionFingerprint")}</TableHead>
                    <TableHead>{t("page.investigations.col.occurred")}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.agent_events.map((event) => (
                    <TableRow key={event.id}>
                      <TableCell>{event.turn}</TableCell>
                      <TableCell>{event.kind}</TableCell>
                      <TableCell className="font-mono text-xs">{event.target}</TableCell>
                      <TableCell>{event.outcome}</TableCell>
                      <TableCell>{event.decision ?? "—"}</TableCell>
                      <TableCell
                        className="font-mono text-xs"
                        title={event.action_fingerprint ?? undefined}
                      >
                        {shortFingerprint(event.action_fingerprint)}
                      </TableCell>
                      <TableCell>{formatUnix(event.occurred_at_unix)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </Section>

          <Section
            title={t("page.investigations.section.billing")}
            count={data.billing_events.length}
          >
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t("page.investigations.col.model")}</TableHead>
                    <TableHead>{t("page.investigations.col.provider")}</TableHead>
                    <TableHead>{t("page.investigations.col.tokens")}</TableHead>
                    <TableHead>{t("page.investigations.col.cost")}</TableHead>
                    <TableHead>{t("page.investigations.col.walletDelta")}</TableHead>
                    <TableHead>{t("common.status")}</TableHead>
                    <TableHead>{t("page.investigations.col.occurred")}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.billing_events.map((billing, index) => (
                    <TableRow key={`${billing.request_id}-${index}`}>
                      <TableCell>{billing.logical_model}</TableCell>
                      <TableCell>{billing.provider}</TableCell>
                      <TableCell>{format.tokens(billing.usage.total_tokens)}</TableCell>
                      <TableCell>
                        {billing.cost_usd !== null && billing.cost_usd !== undefined
                          ? format.currency(billing.cost_usd, "USD", {
                              minimumFractionDigits: 4,
                              maximumFractionDigits: 4,
                            })
                          : "—"}
                      </TableCell>
                      <TableCell>{billing.wallet_delta_credits ?? "—"}</TableCell>
                      <TableCell>{billing.status_code}</TableCell>
                      <TableCell>{formatUnix(billing.occurred_at_unix)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </Section>

          <Section
            title={t("page.investigations.label.auditEvents")}
            count={data.audit_events.length}
          >
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t("page.investigations.col.action")}</TableHead>
                    <TableHead>{t("page.investigations.col.target")}</TableHead>
                    <TableHead>{t("page.investigations.col.outcome")}</TableHead>
                    <TableHead>{t("page.investigations.col.decision")}</TableHead>
                    <TableHead>{t("page.investigations.col.actionFingerprint")}</TableHead>
                    <TableHead>{t("page.investigations.col.occurred")}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.audit_events.map((audit) => (
                    <TableRow key={audit.id}>
                      <TableCell>{audit.action}</TableCell>
                      <TableCell className="font-mono text-xs">{audit.target}</TableCell>
                      <TableCell>{audit.outcome}</TableCell>
                      <TableCell>{audit.decision ?? "—"}</TableCell>
                      <TableCell
                        className="font-mono text-xs"
                        title={audit.action_fingerprint ?? undefined}
                      >
                        {shortFingerprint(audit.action_fingerprint)}
                      </TableCell>
                      <TableCell>{formatUnix(audit.occurred_at_unix)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </Section>

          <Section
            title={t("page.investigations.section.correlations")}
            count={data.action_correlations?.length ?? 0}
            description={t("page.investigations.section.correlationsDescription")}
          >
            {!data.action_correlations || data.action_correlations.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                {t("page.investigations.correlations.empty")}
              </p>
            ) : (
              <div className="flex flex-col gap-3">
                {data.action_correlations.map((group) => (
                  <CorrelationGroup key={group.action_fingerprint} group={group} />
                ))}
              </div>
            )}
          </Section>
        </div>
      )}
    </div>
  );
}
