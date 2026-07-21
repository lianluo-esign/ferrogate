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
import { adminGet } from "@/lib/gateway-client";
import {
  formatUnix,
  shortFingerprint,
  verdictVariant,
  type InvestigationActionCorrelation,
} from "@/lib/guardrails";

type SelectorKind = "request_id" | "trace_id" | "agent_run_id";

const SELECTOR_LABELS: Record<SelectorKind, string> = {
  request_id: "Request ID",
  trace_id: "Trace ID",
  agent_run_id: "Agent run ID",
};

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
  return (
    <li>
      <span className="text-muted-foreground">{label}:</span>{" "}
      {ids.length === 0 ? (
        "none"
      ) : (
        <span className="font-mono text-xs">{ids.join(", ")}</span>
      )}
    </li>
  );
}

/** One shared-action-identity group: fingerprint -> joined evidence ids + child tree (#306/#307). */
function CorrelationGroup({ group }: { group: InvestigationActionCorrelation }) {
  const childRequests = group.child_request_ids ?? [];
  const childDispatches = group.child_dispatch_ids ?? [];
  return (
    <div className="rounded-md border p-3" data-testid="correlation-group">
      <p className="break-all font-mono text-xs">{group.action_fingerprint}</p>
      <ul className="mt-2 space-y-1 border-l pl-4 text-sm">
        <IdList label="Guardrail evaluations" ids={group.guardrail_evaluation_ids} />
        <IdList label="Approvals" ids={group.approval_ids} />
        <IdList label="Timeline events" ids={group.agent_event_ids} />
        <IdList label="Audit events" ids={group.audit_event_ids} />
        {(childRequests.length > 0 || childDispatches.length > 0) && (
          <li>
            <span className="text-muted-foreground">Downstream child actions (#307):</span>
            <ul className="mt-1 space-y-1 border-l pl-4">
              {childRequests.map((id) => (
                <li key={id} className="font-mono text-xs">
                  child request {id}
                </li>
              ))}
              {childDispatches.map((id) => (
                <li key={id} className="font-mono text-xs">
                  child dispatch {id}
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
  const apiKey = session!.gatewayApiKey;

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
        <h1 className="text-lg font-semibold">Investigations</h1>
        <p className="text-sm text-muted-foreground">
          Joined evidence for one request, trace or agent run: identity, requests,
          guardrail evaluations, approvals, timeline, billing, audit events and the
          fingerprint-based action correlation groups (#306, #307).
        </p>
      </div>

      <form className="flex flex-wrap items-end gap-4 rounded-md border p-4" onSubmit={handleSubmit}>
        <div className="grid gap-2">
          <Label htmlFor="investigation-kind">Look up by</Label>
          <Select value={kind} onValueChange={(next) => setKind(next as SelectorKind)}>
            <SelectTrigger id="investigation-kind" className="w-44">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {(Object.keys(SELECTOR_LABELS) as SelectorKind[]).map((option) => (
                <SelectItem key={option} value={option}>
                  {SELECTOR_LABELS[option]}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="grid min-w-64 flex-1 gap-2">
          <Label htmlFor="investigation-value">{SELECTOR_LABELS[kind]}</Label>
          <Input
            id="investigation-value"
            value={value}
            onChange={(event) => setValue(event.target.value)}
            placeholder="req_... / trace-... / run-..."
          />
        </div>
        <Button type="submit">Investigate</Button>
      </form>

      {error && (
        <p role="alert" className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          Investigation failed: {error.message}
        </p>
      )}
      {isLoading && <p className="text-sm text-muted-foreground">Loading investigation…</p>}
      {!applied && !data && (
        <p className="text-sm text-muted-foreground">
          Enter a request, trace or agent run id to load its investigation timeline.
        </p>
      )}

      {data && (
        <div className="flex flex-col gap-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Outcome</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-wrap items-center gap-4 text-sm">
              <Badge variant={verdictVariant(data.final_outcome)}>
                {data.final_outcome}
              </Badge>
              <span className="font-mono text-xs">{data.selector}</span>
              <span>
                <span className="text-muted-foreground">Total cost:</span>{" "}
                ${data.total_cost_usd.toFixed(4)}
              </span>
              {data.identity && (
                <span className="font-mono text-xs">
                  org {data.identity.organization_id ?? "—"} / project{" "}
                  {data.identity.project_id ?? "—"} / key {data.identity.api_key_id ?? "—"}
                </span>
              )}
            </CardContent>
          </Card>

          <Section
            title="Request evidence"
            count={data.requests.length}
            description="Gateway request-log rows, including the upstream parent action fingerprint (#307) when the request declared one."
          >
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Request</TableHead>
                    <TableHead>Route</TableHead>
                    <TableHead>Provider / model</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Error</TableHead>
                    <TableHead>Parent action fingerprint</TableHead>
                    <TableHead>Started</TableHead>
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

          <Section title="Guardrail evaluations" count={data.guardrail_evaluations.length}>
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>ID</TableHead>
                    <TableHead>Policy</TableHead>
                    <TableHead>Stage</TableHead>
                    <TableHead>Verdict</TableHead>
                    <TableHead>Decision</TableHead>
                    <TableHead>Decision reason</TableHead>
                    <TableHead>Action fingerprint</TableHead>
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

          <Section title="Approvals" count={data.approvals.length}>
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>ID</TableHead>
                    <TableHead>Tool</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Decision</TableHead>
                    <TableHead>Decision reason</TableHead>
                    <TableHead>Action fingerprint</TableHead>
                    <TableHead>Requested</TableHead>
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
            title="Timeline"
            count={data.agent_events.length}
            description={`Agent-run events across ${data.agent_runs.length} run(s).`}
          >
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Turn</TableHead>
                    <TableHead>Kind</TableHead>
                    <TableHead>Target</TableHead>
                    <TableHead>Outcome</TableHead>
                    <TableHead>Decision</TableHead>
                    <TableHead>Action fingerprint</TableHead>
                    <TableHead>Occurred</TableHead>
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

          <Section title="Billing entries" count={data.billing_events.length}>
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Model</TableHead>
                    <TableHead>Provider</TableHead>
                    <TableHead>Tokens</TableHead>
                    <TableHead>Cost (USD)</TableHead>
                    <TableHead>Wallet delta</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Occurred</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.billing_events.map((billing, index) => (
                    <TableRow key={`${billing.request_id}-${index}`}>
                      <TableCell>{billing.logical_model}</TableCell>
                      <TableCell>{billing.provider}</TableCell>
                      <TableCell>{billing.usage.total_tokens}</TableCell>
                      <TableCell>
                        {billing.cost_usd !== null && billing.cost_usd !== undefined
                          ? `$${billing.cost_usd.toFixed(4)}`
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

          <Section title="Audit events" count={data.audit_events.length}>
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Action</TableHead>
                    <TableHead>Target</TableHead>
                    <TableHead>Outcome</TableHead>
                    <TableHead>Decision</TableHead>
                    <TableHead>Action fingerprint</TableHead>
                    <TableHead>Occurred</TableHead>
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
            title="Action correlations"
            count={data.action_correlations?.length ?? 0}
            description="Evidence rows sharing one canonical_target_sha256 action fingerprint describe the same external action; child requests/dispatches declared this fingerprint as their parent."
          >
            {!data.action_correlations || data.action_correlations.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                No evidence row in this investigation carries an action fingerprint.
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
