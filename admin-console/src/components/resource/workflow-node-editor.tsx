import { Plus, X } from "lucide-react";
import { EntityReferencePicker } from "@/components/resource/entity-reference-picker";
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
import type { EntityReferenceConfig, ResourceTranslator } from "@/lib/resource-config";
import { useI18n, type TranslationKey } from "@/i18n";

/**
 * Structured reference panel for an agent-workflow `nodes` array (#342).
 *
 * A node's shape is the `AgentWorkflowNode` contract (`deny_unknown_fields`):
 * `{ id, kind, model?, providers?, tool?, max_iterations?, token_budget? }`. The
 * entity references inside a node — the model, its providers, and (for tool
 * nodes) the tool — are edited through the shared #337 picker so operators pick
 * KNOWN entities by name instead of hand-writing ids. Every non-reference node
 * field round-trips unchanged. This is deliberately NOT a graph/DAG editor: the
 * workflow's edges/topology stay a raw JSON field (rewiring the graph is the
 * issue's stated non-goal), so this panel only surfaces the per-node reference
 * arrays.
 */

/** Node kinds from the `AgentWorkflowNodeKind` contract enum. */
export const WORKFLOW_NODE_KINDS = [
  { value: "model", labelKey: "resource.workflowNodes.kind.model" },
  { value: "tool", labelKey: "resource.workflowNodes.kind.tool" },
  { value: "router", labelKey: "resource.workflowNodes.kind.router" },
  { value: "human", labelKey: "resource.workflowNodes.kind.human" },
  { value: "checkpoint", labelKey: "resource.workflowNodes.kind.checkpoint" },
] satisfies { value: string; labelKey: TranslationKey }[];

const MODEL_REFERENCE: EntityReferenceConfig = {
  target: "models",
  valueKey: "name",
  primaryLabelKey: "name",
  secondaryLabelKeys: ["provider", "provider_model"],
  // Historical logs / bespoke configs may name a model no longer in the
  // catalog; allow an exact-id fallback so a stale reference is never silently
  // un-selectable (it still surfaces as an unresolved badge).
  allowRawValue: true,
};

const PROVIDERS_REFERENCE: EntityReferenceConfig = {
  target: "providers",
  valueKey: "name",
  primaryLabelKey: "name",
  secondaryLabelKeys: ["kind"],
  allowRawValue: true,
};

const TOOL_REFERENCE: EntityReferenceConfig = {
  target: "tools",
  valueKey: "name",
  primaryLabelKey: "name",
  secondaryLabelKeys: ["extension_id"],
  allowRawValue: true,
};

export type WorkflowNode = Record<string, unknown>;

function asNodes(value: unknown): WorkflowNode[] {
  return Array.isArray(value)
    ? value.filter((node): node is WorkflowNode => Boolean(node) && typeof node === "object")
    : [];
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.map(String) : [];
}

/**
 * Clean + validate the editor rows into `AgentWorkflowNode` documents before
 * submit (#342). Only contract-known keys are emitted (the node forbids unknown
 * fields), references irrelevant to the selected kind are dropped, and the
 * structural invariants are enforced with operator-facing messages so an
 * incomplete reference is never silently written: every node needs a unique id,
 * a `model` node needs a model, and a `tool` node needs a tool.
 */
export function serializeWorkflowNodes(
  value: unknown,
  t: ResourceTranslator,
): WorkflowNode[] {
  const nodes = asNodes(value);
  const seen = new Set<string>();
  const result: WorkflowNode[] = [];

  for (const node of nodes) {
    const id = String(node.id ?? "").trim();
    const kind = String(node.kind ?? "model").trim() || "model";
    if (id === "") {
      throw new Error(t("resource.workflowNodes.validation.idRequired"));
    }
    if (seen.has(id)) {
      throw new Error(t("resource.workflowNodes.validation.duplicateId", { id }));
    }
    seen.add(id);

    const clean: WorkflowNode = { id, kind };

    if (kind === "model") {
      const model = String(node.model ?? "").trim();
      if (model === "") {
        throw new Error(t("resource.workflowNodes.validation.modelRequired", { id }));
      }
      clean.model = model;
      const providers = asStringArray(node.providers)
        .map((provider) => provider.trim())
        .filter(Boolean);
      if (providers.length > 0) clean.providers = providers;
    } else if (kind === "tool") {
      const tool = String(node.tool ?? "").trim();
      if (tool === "") {
        throw new Error(t("resource.workflowNodes.validation.toolRequired", { id }));
      }
      clean.tool = tool;
    }

    // Numeric limits are valid on any node kind and round-trip unchanged.
    const maxIterations = node.max_iterations;
    if (maxIterations !== undefined && maxIterations !== null && String(maxIterations) !== "") {
      clean.max_iterations = Number(maxIterations);
    }
    const tokenBudget = node.token_budget;
    if (tokenBudget !== undefined && tokenBudget !== null && String(tokenBudget) !== "") {
      clean.token_budget = Number(tokenBudget);
    }

    result.push(clean);
  }

  return result;
}

interface WorkflowNodeEditorProps {
  id: string;
  label: string;
  value: unknown;
  onChange: (nodes: WorkflowNode[]) => void;
}

export function WorkflowNodeEditor({ id, label, value, onChange }: WorkflowNodeEditorProps) {
  const { t } = useI18n();
  const nodes = asNodes(value);
  const lowerLabel = label.toLowerCase();

  function commit(next: WorkflowNode[]) {
    onChange(next);
  }

  function updateNode(index: number, patch: WorkflowNode) {
    commit(nodes.map((node, current) => (current === index ? { ...node, ...patch } : node)));
  }

  function changeKind(index: number, kind: string) {
    // The reference set differs per kind, so clear now-irrelevant references
    // while keeping the node id and numeric limits.
    updateNode(index, { kind, model: "", providers: [], tool: "" });
  }

  function addNode() {
    commit([...nodes, { id: "", kind: "model", model: "", providers: [], tool: "" }]);
  }

  function removeNode(index: number) {
    commit(nodes.filter((_, current) => current !== index));
  }

  return (
    <div className="grid gap-3">
      {nodes.length === 0 ? (
        <p className="text-xs text-muted-foreground">
          {t("resource.workflowNodes.empty")}
        </p>
      ) : (
        <ul className="grid gap-3">
          {nodes.map((node, index) => {
            const kind = String(node.kind ?? "model");
            return (
              <li
                key={index}
                className="grid gap-2 rounded-md border p-3"
                aria-label={t("resource.workflowNodes.nodeLabel", { index: index + 1 })}
              >
                <div className="flex flex-wrap items-start gap-2">
                  <div className="grid min-w-40 flex-1 gap-1.5">
                    <Label htmlFor={`${id}-nodeid-${index}`} className="text-xs">
                      {t("resource.workflowNodes.nodeId")}
                    </Label>
                    <Input
                      id={`${id}-nodeid-${index}`}
                      value={String(node.id ?? "")}
                      autoComplete="off"
                      spellCheck={false}
                      onChange={(event) => updateNode(index, { id: event.target.value })}
                    />
                  </div>
                  <div className="grid min-w-40 flex-1 gap-1.5">
                    <Label htmlFor={`${id}-kind-${index}`} className="text-xs">
                      {t("resource.workflowNodes.kind")}
                    </Label>
                    <Select value={kind} onValueChange={(next) => changeKind(index, next)}>
                      <SelectTrigger id={`${id}-kind-${index}`}>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {WORKFLOW_NODE_KINDS.map((option) => (
                          <SelectItem key={option.value} value={option.value}>
                            {t(option.labelKey)}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="mt-6 size-9 shrink-0"
                    aria-label={t("resource.workflowNodes.remove", { index: index + 1 })}
                    onClick={() => removeNode(index)}
                  >
                    <X className="size-4" aria-hidden="true" />
                  </Button>
                </div>

                {kind === "model" ? (
                  <>
                    <div className="grid gap-1.5">
                      <Label htmlFor={`${id}-model-${index}`} className="text-xs">
                        {t("resource.workflowNodes.model")}
                      </Label>
                      <EntityReferencePicker
                        id={`${id}-model-${index}`}
                        label={t("resource.workflowNodes.model")}
                        reference={MODEL_REFERENCE}
                        value={String(node.model ?? "")}
                        dependencyValues={{}}
                        onChange={(next) =>
                          updateNode(index, { model: typeof next === "string" ? next : "" })
                        }
                      />
                    </div>
                    <div className="grid gap-1.5">
                      <Label htmlFor={`${id}-providers-${index}`} className="text-xs">
                        {t("resource.workflowNodes.providers")}
                      </Label>
                      <EntityReferencePicker
                        id={`${id}-providers-${index}`}
                        label={t("resource.workflowNodes.providers")}
                        reference={PROVIDERS_REFERENCE}
                        value={asStringArray(node.providers)}
                        dependencyValues={{}}
                        multiple
                        onChange={(next) =>
                          updateNode(index, { providers: Array.isArray(next) ? next : [] })
                        }
                      />
                    </div>
                  </>
                ) : kind === "tool" ? (
                  <div className="grid gap-1.5">
                    <Label htmlFor={`${id}-tool-${index}`} className="text-xs">
                      {t("resource.workflowNodes.tool")}
                    </Label>
                    <EntityReferencePicker
                      id={`${id}-tool-${index}`}
                      label={t("resource.workflowNodes.tool")}
                      reference={TOOL_REFERENCE}
                      value={String(node.tool ?? "")}
                      dependencyValues={{}}
                      onChange={(next) =>
                        updateNode(index, { tool: typeof next === "string" ? next : "" })
                      }
                    />
                  </div>
                ) : (
                  <p className="text-xs text-muted-foreground">
                    {t("resource.workflowNodes.noReferences")}
                  </p>
                )}

                <div className="flex flex-wrap gap-2">
                  <div className="grid min-w-32 flex-1 gap-1.5">
                    <Label htmlFor={`${id}-maxiter-${index}`} className="text-xs">
                      {t("resource.workflowNodes.maxIterations")}
                    </Label>
                    <Input
                      id={`${id}-maxiter-${index}`}
                      type="number"
                      min={0}
                      value={node.max_iterations != null ? String(node.max_iterations) : ""}
                      onChange={(event) =>
                        updateNode(index, { max_iterations: event.target.value })
                      }
                    />
                  </div>
                  <div className="grid min-w-32 flex-1 gap-1.5">
                    <Label htmlFor={`${id}-budget-${index}`} className="text-xs">
                      {t("resource.workflowNodes.tokenBudget")}
                    </Label>
                    <Input
                      id={`${id}-budget-${index}`}
                      type="number"
                      min={0}
                      value={node.token_budget != null ? String(node.token_budget) : ""}
                      onChange={(event) =>
                        updateNode(index, { token_budget: event.target.value })
                      }
                    />
                  </div>
                </div>
              </li>
            );
          })}
        </ul>
      )}
      <div>
        <Button type="button" variant="outline" size="sm" onClick={addNode}>
          <Plus className="mr-1 size-4" aria-hidden="true" />
          {t("resource.workflowNodes.add", { label: lowerLabel })}
        </Button>
      </div>
    </div>
  );
}
