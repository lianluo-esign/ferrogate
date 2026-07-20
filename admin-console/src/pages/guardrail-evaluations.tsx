import { useState, type FormEvent } from "react";
import { useQuery } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
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
import { formatUnix, shortFingerprint, verdictVariant } from "@/lib/guardrails";

type Verdict = "pass" | "fail" | "error";
type Action = "allow" | "block" | "redact" | "record";

interface EvaluationFilters {
  request_id: string;
  trace_id: string;
  agent_run_id: string;
  policy_id: string;
  scope_id: string;
  verdict: Verdict | "any";
  action: Action | "any";
}

const EMPTY_FILTERS: EvaluationFilters = {
  request_id: "",
  trace_id: "",
  agent_run_id: "",
  policy_id: "",
  scope_id: "",
  verdict: "any",
  action: "any",
};

function orUndefined(value: string): string | undefined {
  return value.trim() === "" ? undefined : value.trim();
}

export default function GuardrailEvaluationsPage() {
  const { session } = useAuth();
  const apiKey = session!.gatewayApiKey;

  const [form, setForm] = useState<EvaluationFilters>(EMPTY_FILTERS);
  const [applied, setApplied] = useState<EvaluationFilters>(EMPTY_FILTERS);

  const { data, isLoading, error } = useQuery({
    queryKey: ["guardrail-evaluations", applied],
    queryFn: () =>
      adminGet(apiKey, "/admin/v1/guardrail-evaluations", {
        query: {
          request_id: orUndefined(applied.request_id),
          trace_id: orUndefined(applied.trace_id),
          agent_run_id: orUndefined(applied.agent_run_id),
          policy_id: orUndefined(applied.policy_id),
          scope_id: orUndefined(applied.scope_id),
          verdict: applied.verdict === "any" ? undefined : applied.verdict,
          action: applied.action === "any" ? undefined : applied.action,
        },
      }),
  });

  function setField<K extends keyof EvaluationFilters>(
    key: K,
    value: EvaluationFilters[K],
  ) {
    setForm((current) => ({ ...current, [key]: value }));
  }

  function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setApplied(form);
  }

  const rows = data?.data ?? [];

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold">Guardrail evaluations</h1>
        <p className="text-sm text-muted-foreground">
          Sanitized guardrail evaluation evidence (no matched text). Includes the stored
          canonical decision, decision reason and target-level action fingerprint (#306)
          alongside the recorded verdict / action / enforcement triple.
        </p>
      </div>

      <form className="grid gap-4 rounded-md border p-4 sm:grid-cols-3" onSubmit={handleSubmit}>
        <div className="grid gap-2">
          <Label htmlFor="filter-request-id">Request ID</Label>
          <Input
            id="filter-request-id"
            value={form.request_id}
            onChange={(event) => setField("request_id", event.target.value)}
            placeholder="req_..."
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor="filter-trace-id">Trace ID</Label>
          <Input
            id="filter-trace-id"
            value={form.trace_id}
            onChange={(event) => setField("trace_id", event.target.value)}
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor="filter-agent-run-id">Agent run ID</Label>
          <Input
            id="filter-agent-run-id"
            value={form.agent_run_id}
            onChange={(event) => setField("agent_run_id", event.target.value)}
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor="filter-policy-id">Policy ID</Label>
          <Input
            id="filter-policy-id"
            value={form.policy_id}
            onChange={(event) => setField("policy_id", event.target.value)}
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor="filter-scope-id">Scope ID (tenant / project / key)</Label>
          <Input
            id="filter-scope-id"
            value={form.scope_id}
            onChange={(event) => setField("scope_id", event.target.value)}
            placeholder="tenant-..."
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor="filter-verdict">Verdict</Label>
          <Select
            value={form.verdict}
            onValueChange={(value) => setField("verdict", value as Verdict | "any")}
          >
            <SelectTrigger id="filter-verdict">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="any">any</SelectItem>
              <SelectItem value="pass">pass</SelectItem>
              <SelectItem value="fail">fail</SelectItem>
              <SelectItem value="error">error</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="grid gap-2">
          <Label htmlFor="filter-action">Action</Label>
          <Select
            value={form.action}
            onValueChange={(value) => setField("action", value as Action | "any")}
          >
            <SelectTrigger id="filter-action">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="any">any</SelectItem>
              <SelectItem value="allow">allow</SelectItem>
              <SelectItem value="block">block</SelectItem>
              <SelectItem value="redact">redact</SelectItem>
              <SelectItem value="record">record</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="flex items-end gap-2">
          <Button type="submit">Apply filters</Button>
          <Button
            type="button"
            variant="outline"
            onClick={() => {
              setForm(EMPTY_FILTERS);
              setApplied(EMPTY_FILTERS);
            }}
          >
            Reset
          </Button>
        </div>
      </form>

      {error && (
        <p className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          Failed to load guardrail evaluations: {error.message}
        </p>
      )}

      {data && (
        <p className="text-sm text-muted-foreground">
          {data.total} evaluation{data.total === 1 ? "" : "s"} matched.
        </p>
      )}

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Occurred</TableHead>
              <TableHead>Request</TableHead>
              <TableHead>Policy</TableHead>
              <TableHead>Stage</TableHead>
              <TableHead>Verdict</TableHead>
              <TableHead>Action</TableHead>
              <TableHead>Enforcement</TableHead>
              <TableHead>Decision</TableHead>
              <TableHead>Decision reason</TableHead>
              <TableHead>Action fingerprint</TableHead>
              <TableHead>Findings</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={11} className="h-24 text-center">
                  Loading...
                </TableCell>
              </TableRow>
            ) : rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={11} className="h-24 text-center">
                  No guardrail evaluations match the current filters.
                </TableCell>
              </TableRow>
            ) : (
              rows.map((row) => (
                <TableRow key={row.id}>
                  <TableCell className="whitespace-nowrap">
                    {formatUnix(row.occurred_at_unix)}
                  </TableCell>
                  <TableCell className="font-mono text-xs">{row.request_id}</TableCell>
                  <TableCell className="font-mono text-xs">
                    {row.policy_id}@r{row.policy_revision}
                  </TableCell>
                  <TableCell>{row.stage}</TableCell>
                  <TableCell>
                    <Badge variant={verdictVariant(row.verdict)}>{row.verdict}</Badge>
                  </TableCell>
                  <TableCell>{row.action}</TableCell>
                  <TableCell>{row.enforcement_status}</TableCell>
                  <TableCell>
                    {row.decision ? (
                      <Badge variant={verdictVariant(row.decision)}>{row.decision}</Badge>
                    ) : (
                      "—"
                    )}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {row.decision_reason ?? "—"}
                  </TableCell>
                  <TableCell className="font-mono text-xs" title={row.action_fingerprint ?? undefined}>
                    {shortFingerprint(row.action_fingerprint)}
                  </TableCell>
                  <TableCell>{row.finding_count}</TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
