import { useState, type FormEvent } from "react";
import { useQuery } from "@tanstack/react-query";
import { EntityReferencePicker } from "@/components/resource/entity-reference-picker";
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
import { useI18n } from "@/i18n";
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
  const { t, format } = useI18n();
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
        <h1 className="text-lg font-semibold">{t("page.guardrailEvaluations.title")}</h1>
        <p className="text-sm text-muted-foreground">
          {t("page.guardrailEvaluations.description")}
        </p>
      </div>

      <form className="grid gap-4 rounded-md border p-4 sm:grid-cols-3" onSubmit={handleSubmit}>
        <div className="grid gap-2">
          <Label htmlFor="filter-request-id">{t("page.guardrailEvaluations.filter.requestId")}</Label>
          <Input
            id="filter-request-id"
            value={form.request_id}
            onChange={(event) => setField("request_id", event.target.value)}
            // eslint-disable-next-line ferrogate/no-untranslated-literal -- example ID-prefix format hint, identical in every locale
            placeholder="req_..."
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor="filter-trace-id">{t("page.guardrailEvaluations.filter.traceId")}</Label>
          <Input
            id="filter-trace-id"
            value={form.trace_id}
            onChange={(event) => setField("trace_id", event.target.value)}
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor="filter-agent-run-id">{t("page.guardrailEvaluations.filter.agentRunId")}</Label>
          <Input
            id="filter-agent-run-id"
            value={form.agent_run_id}
            onChange={(event) => setField("agent_run_id", event.target.value)}
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor="filter-policy-id">{t("page.guardrailEvaluations.filter.policyId")}</Label>
          {/* #341: the policy filter is a real, queryable entity
              (GET /admin/v1/guardrail-policies), so it uses the shared reference
              picker — operators search by policy name instead of pasting a raw
              id, the applied id still drives the log query, and a deleted policy
              stays visible as an unresolved badge. */}
          <EntityReferencePicker
            id="filter-policy-id"
            label={t("page.guardrailEvaluations.filter.policyId")}
            reference={{
              target: "guardrail-policies",
              valueKey: "policy_id",
              primaryLabelKey: "name",
            }}
            value={form.policy_id}
            dependencyValues={{}}
            onChange={(value) =>
              setField("policy_id", typeof value === "string" ? value : (value[0] ?? ""))
            }
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor="filter-scope-id">{t("page.guardrailEvaluations.filter.scopeId")}</Label>
          {/* #341 (justified, no silent exclusion): scope_id here is a
              polymorphic observability correlation input, not an entity-backed
              config field. Evaluation rows carry every scope kind (tenant /
              project / workspace / key / service-account …) and this filter has
              no scope_type discriminator, so there is no single entity kind to
              build a picker over. Adding a scope_type dimension would change the
              log query contract (a #341 non-goal: "redesigning runtime
              semantics"), so this stays a free-text correlation box. */}
          <Input
            id="filter-scope-id"
            value={form.scope_id}
            onChange={(event) => setField("scope_id", event.target.value)}
            // eslint-disable-next-line ferrogate/no-untranslated-literal -- example ID-prefix format hint, identical in every locale
            placeholder="tenant-..."
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor="filter-verdict">{t("page.guardrailEvaluations.filter.verdict")}</Label>
          <Select
            value={form.verdict}
            onValueChange={(value) => setField("verdict", value as Verdict | "any")}
          >
            <SelectTrigger id="filter-verdict">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="any">{t("page.guardrailEvaluations.option.any")}</SelectItem>
              <SelectItem value="pass">{t("page.guardrailEvaluations.verdict.pass")}</SelectItem>
              <SelectItem value="fail">{t("page.guardrailEvaluations.verdict.fail")}</SelectItem>
              <SelectItem value="error">{t("page.guardrailEvaluations.verdict.error")}</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="grid gap-2">
          <Label htmlFor="filter-action">{t("page.guardrailEvaluations.filter.action")}</Label>
          <Select
            value={form.action}
            onValueChange={(value) => setField("action", value as Action | "any")}
          >
            <SelectTrigger id="filter-action">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="any">{t("page.guardrailEvaluations.option.any")}</SelectItem>
              <SelectItem value="allow">{t("page.guardrailEvaluations.action.allow")}</SelectItem>
              <SelectItem value="block">{t("page.guardrailEvaluations.action.block")}</SelectItem>
              <SelectItem value="redact">{t("page.guardrailEvaluations.action.redact")}</SelectItem>
              <SelectItem value="record">{t("page.guardrailEvaluations.action.record")}</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="flex items-end gap-2">
          <Button type="submit">{t("page.guardrailEvaluations.filter.apply")}</Button>
          <Button
            type="button"
            variant="outline"
            onClick={() => {
              setForm(EMPTY_FILTERS);
              setApplied(EMPTY_FILTERS);
            }}
          >
            {t("page.guardrailEvaluations.filter.reset")}
          </Button>
        </div>
      </form>

      {error && (
        <p role="alert" className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {t("page.guardrailEvaluations.loadError", { message: error.message })}
        </p>
      )}

      {data && (
        <p className="text-sm text-muted-foreground">
          {format.plural(data.total, {
            one: t("page.guardrailEvaluations.matched.one", { count: data.total }),
            other: t("page.guardrailEvaluations.matched.other", { count: data.total }),
          })}
        </p>
      )}

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t("page.guardrailEvaluations.col.occurred")}</TableHead>
              <TableHead>{t("page.guardrailEvaluations.col.request")}</TableHead>
              <TableHead>{t("page.guardrailEvaluations.col.policy")}</TableHead>
              <TableHead>{t("page.guardrailEvaluations.col.stage")}</TableHead>
              <TableHead>{t("page.guardrailEvaluations.col.verdict")}</TableHead>
              <TableHead>{t("page.guardrailEvaluations.col.action")}</TableHead>
              <TableHead>{t("page.guardrailEvaluations.col.enforcement")}</TableHead>
              <TableHead>{t("page.guardrailEvaluations.col.decision")}</TableHead>
              <TableHead>{t("page.guardrailEvaluations.col.decisionReason")}</TableHead>
              <TableHead>{t("page.guardrailEvaluations.col.actionFingerprint")}</TableHead>
              <TableHead>{t("page.guardrailEvaluations.col.findings")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={11} className="h-24 text-center">
                  {t("resource.table.loading")}
                </TableCell>
              </TableRow>
            ) : rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={11} className="h-24 text-center">
                  {t("page.guardrailEvaluations.empty")}
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
