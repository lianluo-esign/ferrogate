import { useEffect, useRef, useState } from "react";
import { EntityReferencePicker } from "@/components/resource/entity-reference-picker";
import { ReferenceListEditor } from "@/components/resource/reference-list-editor";
import {
  serializeWorkflowNodes,
  WorkflowNodeEditor,
} from "@/components/resource/workflow-node-editor";
import { AsyncStatus } from "@/components/ui/async-status";
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
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import {
  clearDependentReferenceValues,
  resolveActiveReference,
  resolveConfigText,
  resolveOptionalConfigText,
  type FieldConfig,
} from "@/lib/resource-config";
import { useI18n } from "@/i18n";

interface ResourceFormProps {
  fields: FieldConfig[];
  initialValues: Record<string, unknown>;
  submitLabel: string;
  isEdit?: boolean;
  onSubmit: (values: Record<string, unknown>) => Promise<void>;
  onCancel: () => void;
}

function normalizeInitialValues(
  fields: FieldConfig[],
  initialValues: Record<string, unknown>,
): Record<string, unknown> {
  const normalized: Record<string, unknown> = { ...initialValues };
  for (const field of fields) {
    const raw = normalized[field.name];
    if (field.type === "json" && raw !== undefined && typeof raw !== "string") {
      normalized[field.name] = JSON.stringify(raw, null, 2);
    } else if (
      (field.type === "entities" ||
        field.type === "reference-list" ||
        field.type === "workflow-nodes") &&
      !Array.isArray(raw)
    ) {
      normalized[field.name] = [];
    }
  }
  return normalized;
}

function fieldValuesEqual(previous: unknown, next: unknown): boolean {
  if (!Array.isArray(previous) || !Array.isArray(next)) return previous === next;
  return (
    previous.length === next.length &&
    previous.every((value, index) => value === next[index])
  );
}

export function ResourceForm({
  fields,
  initialValues,
  submitLabel,
  isEdit,
  onSubmit,
  onCancel,
}: ResourceFormProps) {
  const { t } = useI18n();
  const [values, setValues] = useState<Record<string, unknown>>(() =>
    normalizeInitialValues(fields, initialValues),
  );
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const errorRef = useRef<HTMLParagraphElement>(null);

  useEffect(() => {
    if (error) errorRef.current?.focus();
  }, [error]);

  const visibleFields = fields.filter((field) => !(isEdit && field.createOnly));

  function setField(name: string, value: unknown) {
    setValues((previous) => {
      if (fieldValuesEqual(previous[name], value)) return previous;
      return clearDependentReferenceValues(fields, { ...previous, [name]: value }, name);
    });
  }

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const payload: Record<string, unknown> = {};
      for (const field of visibleFields) {
        const raw = values[field.name];
        if (
          field.required &&
          (raw === "" || raw === undefined || (Array.isArray(raw) && raw.length === 0))
        ) {
          throw new Error(
            t("resource.validation.required", {
              field: resolveConfigText(t, field.labelKey, field.label),
            }),
          );
        }
        if (field.type === "json" && typeof raw === "string" && raw.trim() !== "") {
          try {
            payload[field.name] = JSON.parse(raw);
          } catch {
            throw new Error(
              t("resource.validation.invalidJson", {
                field: resolveConfigText(t, field.labelKey, field.label),
              }),
            );
          }
        } else if (field.type === "reference-list") {
          // Emit the structured reference array (#342): keep only rows that
          // carry both a kind and an id, trim string values, and drop
          // empty-string extras so an untouched optional field submits as
          // absent rather than "". Unknown keys spread through unchanged so any
          // non-reference document fields the console does not model round-trip.
          const rows = Array.isArray(raw) ? raw : [];
          payload[field.name] = rows
            .filter((row): row is Record<string, unknown> => Boolean(row) && typeof row === "object")
            .map((row) => {
              const cleaned: Record<string, unknown> = {};
              for (const [key, entry] of Object.entries(row)) {
                if (typeof entry === "string") {
                  const trimmed = entry.trim();
                  if (trimmed !== "") cleaned[key] = trimmed;
                } else if (entry !== undefined && entry !== null) {
                  cleaned[key] = entry;
                }
              }
              return cleaned;
            })
            .filter(
              (row) =>
                String(row[field.discriminantKey] ?? "") !== "" &&
                String(row[field.valueKey] ?? "") !== "",
            );
        } else if (field.type === "workflow-nodes") {
          // Emit the structured `AgentWorkflowNode` array (#342): clean each
          // node down to its contract-known keys, drop references irrelevant to
          // the chosen kind, and validate the structural invariants (unique id;
          // model/tool present for their kind) so an incomplete reference is
          // rejected before submit rather than silently written.
          payload[field.name] = serializeWorkflowNodes(raw, t);
        } else if (field.type === "csv") {
          payload[field.name] = String(raw ?? "")
            .split(",")
            .map((item) => item.trim())
            .filter(Boolean);
        } else if (field.type === "number" && raw !== "" && raw !== undefined) {
          payload[field.name] = Number(raw);
        } else if (raw !== "") {
          payload[field.name] = raw;
        }
      }
      await onSubmit(payload);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("resource.form.saveError"));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-4">
      {visibleFields.map((field) => {
        // Per-field copy prefers the typed catalog key (migrated resources) and
        // falls back to the legacy inline literal otherwise (#348).
        const fieldLabel = resolveConfigText(t, field.labelKey, field.label);
        const fieldPlaceholder = resolveOptionalConfigText(
          t,
          field.placeholderKey,
          field.placeholder,
        );
        const fieldDescription = resolveOptionalConfigText(
          t,
          field.descriptionKey,
          field.description,
        );
        return (
        <div key={field.name} className="grid gap-2">
          <Label htmlFor={field.name}>
            {fieldLabel}
            {field.required ? " *" : ""}
          </Label>
          {field.type === "boolean" ? (
            <Switch
              id={field.name}
              name={field.name}
              checked={Boolean(values[field.name])}
              onCheckedChange={(checked) => setField(field.name, checked)}
            />
          ) : field.type === "select" ? (
            <Select
              name={field.name}
              value={String(values[field.name] ?? "")}
              onValueChange={(value) => setField(field.name, value)}
            >
              <SelectTrigger id={field.name}>
                <SelectValue placeholder={fieldPlaceholder ?? t("resource.form.selectPlaceholder")} />
              </SelectTrigger>
              <SelectContent>
                {field.options?.map((option) => (
                  <SelectItem key={option.value} value={option.value}>
                    {resolveConfigText(t, option.labelKey, option.label)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          ) : field.type === "entity" || field.type === "entities" ? (
            (() => {
              // A scoped reference resolves its target kind from a sibling field
              // (#341); until that sibling is chosen there is nothing to list, so
              // the picker is disabled with a "select {scope} first" prompt that
              // mirrors the picker's own missing-dependency affordance.
              const activeReference = resolveActiveReference(field, values);
              if (!activeReference) {
                const scopeField = fields.find(
                  (candidate) => candidate.name === field.scopedReference?.field,
                );
                const scopeLabel = scopeField
                  ? resolveConfigText(t, scopeField.labelKey, scopeField.label)
                  : "";
                return (
                  <Button
                    id={field.name}
                    type="button"
                    variant="outline"
                    role="combobox"
                    aria-expanded={false}
                    aria-required={field.required}
                    disabled
                    className="h-auto min-h-10 w-full justify-start px-3 py-2 font-normal text-muted-foreground"
                  >
                    {t("resource.picker.selectDependencyFirst", { name: scopeLabel })}
                  </Button>
                );
              }
              return (
                <EntityReferencePicker
                  id={field.name}
                  label={fieldLabel}
                  reference={activeReference}
                  value={values[field.name]}
                  dependencyValues={values}
                  multiple={field.type === "entities"}
                  required={field.required}
                  placeholder={fieldPlaceholder}
                  onChange={(value) => setField(field.name, value)}
                />
              );
            })()
          ) : field.type === "reference-list" ? (
            <ReferenceListEditor
              id={field.name}
              label={fieldLabel}
              field={field}
              value={values[field.name]}
              onChange={(rows) => setField(field.name, rows)}
            />
          ) : field.type === "workflow-nodes" ? (
            <WorkflowNodeEditor
              id={field.name}
              label={fieldLabel}
              value={values[field.name]}
              onChange={(nodes) => setField(field.name, nodes)}
            />
          ) : field.type === "textarea" || field.type === "json" ? (
            <Textarea
              id={field.name}
              name={field.name}
              autoComplete={field.autoComplete ?? "off"}
              inputMode={field.inputMode}
              spellCheck={field.spellCheck ?? field.type === "textarea"}
              required={field.required}
              placeholder={fieldPlaceholder}
              value={String(values[field.name] ?? "")}
              onChange={(event) => setField(field.name, event.target.value)}
              rows={field.type === "json" ? 6 : 3}
            />
          ) : (
            <Input
              id={field.name}
              name={field.name}
              type={field.type === "number" ? "number" : "text"}
              autoComplete={field.autoComplete ?? "off"}
              inputMode={field.inputMode ?? (field.type === "number" ? "decimal" : "text")}
              spellCheck={field.spellCheck ?? false}
              required={field.required}
              placeholder={fieldPlaceholder}
              value={String(values[field.name] ?? "")}
              onChange={(event) => setField(field.name, event.target.value)}
            />
          )}
          {fieldDescription && (
            <p className="text-xs text-muted-foreground">{fieldDescription}</p>
          )}
        </div>
        );
      })}
      {error ? (
        <AsyncStatus ref={errorRef} tone="error">
          {error}
        </AsyncStatus>
      ) : null}
      <div className="flex justify-end gap-2 pt-2">
        <Button type="button" variant="outline" onClick={onCancel}>
          {t("resource.action.cancel")}
        </Button>
        <Button type="submit" disabled={submitting}>
          {submitting ? t("resource.action.saving") : submitLabel}
        </Button>
      </div>
    </form>
  );
}
