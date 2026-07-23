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
import { Textarea } from "@/components/ui/textarea";
import {
  resolveConfigText,
  resolveOptionalConfigText,
  type ReferenceListFieldConfig,
  type ReferenceListKind,
} from "@/lib/resource-config";
import { useI18n } from "@/i18n";

interface ReferenceListEditorProps {
  id: string;
  /** Already-resolved field label (used for row/add/remove copy). */
  label: string;
  field: ReferenceListFieldConfig;
  value: unknown;
  onChange: (rows: Record<string, unknown>[]) => void;
}

type Row = Record<string, unknown>;

function asRows(value: unknown): Row[] {
  return Array.isArray(value)
    ? value.filter((row): row is Row => Boolean(row) && typeof row === "object")
    : [];
}

/**
 * Structured editor for an array of typed references embedded in a JSON
 * document (#342). Each row selects a kind (the discriminant) and, for kinds
 * backed by an entity catalog, resolves the referenced id through the shared
 * #337 picker so operators never hand-copy ids; kinds with no list/get API fall
 * back to a validated raw-id input. Per-row non-reference fields (`extraFields`)
 * and any keys the console does not model are spread through unchanged, so the
 * surrounding document round-trips. Switching a row's kind clears its now-stale
 * id (the new kind lists a different entity) while preserving the extras.
 */
export function ReferenceListEditor({
  id,
  label,
  field,
  value,
  onChange,
}: ReferenceListEditorProps) {
  const { t } = useI18n();
  const rows = asRows(value);
  const lowerLabel = label.toLowerCase();

  function commit(next: Row[]) {
    onChange(next);
  }

  function updateRow(index: number, patch: Row) {
    commit(rows.map((row, current) => (current === index ? { ...row, ...patch } : row)));
  }

  function changeKind(index: number, kind: string) {
    // The new kind lists a different entity, so the previously-selected id no
    // longer resolves — clear it while keeping the row's extra fields.
    updateRow(index, { [field.discriminantKey]: kind, [field.valueKey]: "" });
  }

  function addRow() {
    commit([
      ...rows,
      { [field.discriminantKey]: field.kinds[0]?.value ?? "", [field.valueKey]: "" },
    ]);
  }

  function removeRow(index: number) {
    commit(rows.filter((_, current) => current !== index));
  }

  function kindOf(row: Row): ReferenceListKind | undefined {
    return field.kinds.find((kind) => kind.value === String(row[field.discriminantKey] ?? ""));
  }

  return (
    <div className="grid gap-3">
      {rows.length === 0 ? (
        <p className="text-xs text-muted-foreground">
          {t("resource.referenceList.empty", { label: lowerLabel })}
        </p>
      ) : (
        <ul className="grid gap-3">
          {rows.map((row, index) => {
            const kind = kindOf(row);
            const kindLabel = kind
              ? resolveConfigText(t, kind.labelKey, kind.label)
              : String(row[field.discriminantKey] ?? "");
            const rowValue = String(row[field.valueKey] ?? "");
            return (
              <li
                key={index}
                className="grid gap-2 rounded-md border p-3"
                aria-label={t("resource.referenceList.rowLabel", {
                  label,
                  index: index + 1,
                })}
              >
                <div className="flex flex-wrap items-start gap-2">
                  <div className="grid min-w-40 flex-1 gap-1.5">
                    <Label htmlFor={`${id}-kind-${index}`} className="text-xs">
                      {t("resource.referenceList.kind")}
                    </Label>
                    <Select
                      value={String(row[field.discriminantKey] ?? "")}
                      onValueChange={(kindValue) => changeKind(index, kindValue)}
                    >
                      <SelectTrigger id={`${id}-kind-${index}`}>
                        <SelectValue placeholder={t("resource.form.selectPlaceholder")} />
                      </SelectTrigger>
                      <SelectContent>
                        {field.kinds.map((option) => (
                          <SelectItem key={option.value} value={option.value}>
                            {resolveConfigText(t, option.labelKey, option.label)}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="grid min-w-52 flex-[2] gap-1.5">
                    <Label htmlFor={`${id}-ref-${index}`} className="text-xs">
                      {t("resource.referenceList.reference")}
                    </Label>
                    {kind?.reference ? (
                      <EntityReferencePicker
                        id={`${id}-ref-${index}`}
                        label={kindLabel}
                        reference={kind.reference}
                        value={rowValue}
                        dependencyValues={{}}
                        onChange={(next) =>
                          updateRow(index, {
                            [field.valueKey]: typeof next === "string" ? next : "",
                          })
                        }
                      />
                    ) : (
                      <Input
                        id={`${id}-ref-${index}`}
                        value={rowValue}
                        autoComplete="off"
                        spellCheck={false}
                        aria-label={t("resource.referenceList.reference")}
                        placeholder={t("resource.referenceList.rawIdPlaceholder")}
                        onChange={(event) =>
                          updateRow(index, { [field.valueKey]: event.target.value })
                        }
                      />
                    )}
                  </div>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="mt-6 size-9 shrink-0"
                    aria-label={t("resource.referenceList.remove", {
                      label: lowerLabel,
                      index: index + 1,
                    })}
                    onClick={() => removeRow(index)}
                  >
                    <X className="size-4" aria-hidden="true" />
                  </Button>
                </div>
                {field.extraFields?.map((extra) => {
                  const extraLabel = resolveConfigText(t, extra.labelKey, extra.label);
                  const extraPlaceholder = resolveOptionalConfigText(
                    t,
                    extra.placeholderKey,
                    extra.placeholder,
                  );
                  const extraId = `${id}-${extra.key}-${index}`;
                  return (
                    <div key={extra.key} className="grid gap-1.5">
                      <Label htmlFor={extraId} className="text-xs">
                        {extraLabel}
                      </Label>
                      {extra.type === "textarea" ? (
                        <Textarea
                          id={extraId}
                          rows={2}
                          value={String(row[extra.key] ?? "")}
                          placeholder={extraPlaceholder}
                          onChange={(event) =>
                            updateRow(index, { [extra.key]: event.target.value })
                          }
                        />
                      ) : (
                        <Input
                          id={extraId}
                          value={String(row[extra.key] ?? "")}
                          autoComplete="off"
                          placeholder={extraPlaceholder}
                          onChange={(event) =>
                            updateRow(index, { [extra.key]: event.target.value })
                          }
                        />
                      )}
                    </div>
                  );
                })}
              </li>
            );
          })}
        </ul>
      )}
      <div>
        <Button type="button" variant="outline" size="sm" onClick={addRow}>
          <Plus className="mr-1 size-4" aria-hidden="true" />
          {t("resource.referenceList.add", { label: lowerLabel })}
        </Button>
      </div>
    </div>
  );
}
