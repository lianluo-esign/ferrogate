import { CatalogScopeToggle } from "@/components/resource/catalog-scope-toggle";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
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
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useCatalogApiKey } from "@/hooks/use-catalog-api-key";
import { useCatalogScope } from "@/hooks/use-catalog-scope";
import { useOperatorError } from "@/hooks/use-operator-error";
import { type TranslationKey, useI18n } from "@/i18n";
import { type AdminSchema, adminDelete, adminGet, adminPost, adminPut } from "@/lib/gateway-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
// Nested model-offerings CRUD (#912 slice 2c): the admin surface over
// GET/POST /admin/v1/models/{model_id}/offerings and
// GET/PUT/PATCH/DELETE /admin/v1/models/{model_id}/offerings/{offering_id}.
// Reached from the models list (each row's name links here) or by direct URL.
//
// This page REUSES slice 2a's platform-scope machinery: `useCatalogApiKey()`
// returns the platform-operator key under platform scope (superadmin only) and
// the tenant gateway key otherwise, and `<CatalogScopeToggle>` flips between the
// two. The console never sends a `tenant_id`; the backend resolves catalog scope
// purely from WHICH credential asked, and every response carries `scope`. The
// list query keys on the active scope so toggling refetches the OTHER catalog.
//
// provider_id and upstream_model_id are plain TEXT inputs on purpose — the
// shared entity-reference-picker hard-codes the tenant credential and would list
// TENANT providers even under platform scope, so it cannot be used here.
import { useMemo, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { toast } from "sonner";

type Offering = AdminSchema<"AdminOffering">;
type OfferingMutation = AdminSchema<"AdminModelOfferingMutation">;

interface OfferingFormState {
  provider_id: string;
  upstream_model_id: string;
  role: string;
  priority: string;
  weight: string;
  canary_percent: string;
  shadow_percent: string;
  capabilities: string;
  context_window: string;
  region: string;
  input_price_per_1m: string;
  output_price_per_1m: string;
  cached_input_price_per_1m: string;
  cache_write_price_per_1m: string;
  reasoning_price_per_1m: string;
  audio_second_price_per_1m: string;
  audio_character_price_per_1m: string;
  currency: string;
  source: string;
  enabled: boolean;
}

/** Text/number/csv form fields, in display order. `enabled` (a Switch) and
 *  `role` (a Select) are rendered separately. */
type ScalarFieldKey = Exclude<keyof OfferingFormState, "enabled" | "role">;

interface ScalarField {
  name: ScalarFieldKey;
  labelKey: TranslationKey;
  kind: "text" | "number";
  required?: boolean;
  placeholderKey?: TranslationKey;
}

const SCALAR_FIELDS: readonly ScalarField[] = [
  {
    name: "provider_id",
    labelKey: "page.modelOfferings.field.providerId",
    kind: "text",
    required: true,
    placeholderKey: "page.modelOfferings.field.providerId.placeholder",
  },
  {
    name: "upstream_model_id",
    labelKey: "page.modelOfferings.field.upstreamModelId",
    kind: "text",
    required: true,
    placeholderKey: "page.modelOfferings.field.upstreamModelId.placeholder",
  },
  { name: "priority", labelKey: "page.modelOfferings.field.priority", kind: "number" },
  { name: "weight", labelKey: "page.modelOfferings.field.weight", kind: "number" },
  { name: "canary_percent", labelKey: "page.modelOfferings.field.canaryPercent", kind: "number" },
  { name: "shadow_percent", labelKey: "page.modelOfferings.field.shadowPercent", kind: "number" },
  {
    name: "capabilities",
    labelKey: "page.modelOfferings.field.capabilities",
    kind: "text",
    placeholderKey: "page.modelOfferings.field.capabilities.placeholder",
  },
  { name: "context_window", labelKey: "page.modelOfferings.field.contextWindow", kind: "number" },
  { name: "region", labelKey: "page.modelOfferings.field.region", kind: "text" },
  { name: "input_price_per_1m", labelKey: "page.modelOfferings.field.inputPrice", kind: "number" },
  {
    name: "output_price_per_1m",
    labelKey: "page.modelOfferings.field.outputPrice",
    kind: "number",
  },
  {
    name: "cached_input_price_per_1m",
    labelKey: "page.modelOfferings.field.cachedInputPrice",
    kind: "number",
  },
  {
    name: "cache_write_price_per_1m",
    labelKey: "page.modelOfferings.field.cacheWritePrice",
    kind: "number",
  },
  {
    name: "reasoning_price_per_1m",
    labelKey: "page.modelOfferings.field.reasoningPrice",
    kind: "number",
  },
  {
    name: "audio_second_price_per_1m",
    labelKey: "page.modelOfferings.field.audioSecondPrice",
    kind: "number",
  },
  {
    name: "audio_character_price_per_1m",
    labelKey: "page.modelOfferings.field.audioCharacterPrice",
    kind: "number",
  },
  { name: "currency", labelKey: "page.modelOfferings.field.currency", kind: "text" },
  { name: "source", labelKey: "page.modelOfferings.field.source", kind: "text" },
];

const ROLE_OPTIONS: readonly { value: string; labelKey: TranslationKey }[] = [
  { value: "primary", labelKey: "page.modelOfferings.option.role.primary" },
  { value: "fallback", labelKey: "page.modelOfferings.option.role.fallback" },
  { value: "canary", labelKey: "page.modelOfferings.option.role.canary" },
  { value: "shadow", labelKey: "page.modelOfferings.option.role.shadow" },
];

function emptyForm(): OfferingFormState {
  return {
    provider_id: "",
    upstream_model_id: "",
    role: "",
    priority: "",
    weight: "",
    canary_percent: "",
    shadow_percent: "",
    capabilities: "",
    context_window: "",
    region: "",
    input_price_per_1m: "",
    output_price_per_1m: "",
    cached_input_price_per_1m: "",
    cache_write_price_per_1m: "",
    reasoning_price_per_1m: "",
    audio_second_price_per_1m: "",
    audio_character_price_per_1m: "",
    currency: "",
    source: "",
    enabled: true,
  };
}

/** A stringified value (empty for null/undefined) for editing an existing row. */
function str(value: unknown): string {
  return value === null || value === undefined ? "" : String(value);
}

function formFromOffering(offering: Offering): OfferingFormState {
  return {
    provider_id: str(offering.provider_id),
    upstream_model_id: str(offering.upstream_model_id),
    role: str(offering.role),
    priority: str(offering.priority),
    weight: str(offering.weight),
    canary_percent: str(offering.canary_percent),
    shadow_percent: str(offering.shadow_percent),
    capabilities: (offering.capabilities ?? []).join(", "),
    context_window: str(offering.context_window),
    region: str(offering.region),
    input_price_per_1m: str(offering.input_price_per_1m),
    output_price_per_1m: str(offering.output_price_per_1m),
    cached_input_price_per_1m: str(offering.cached_input_price_per_1m),
    cache_write_price_per_1m: str(offering.cache_write_price_per_1m),
    reasoning_price_per_1m: str(offering.reasoning_price_per_1m),
    audio_second_price_per_1m: str(offering.audio_second_price_per_1m),
    audio_character_price_per_1m: str(offering.audio_character_price_per_1m),
    currency: str(offering.currency),
    source: str(offering.source),
    enabled: offering.enabled,
  };
}

/** Parse a trimmed numeric field; `undefined` when blank or not finite. */
function numOrUndefined(value: string): number | undefined {
  const trimmed = value.trim();
  if (trimmed === "") return undefined;
  const parsed = Number(trimmed);
  return Number.isFinite(parsed) ? parsed : undefined;
}

/**
 * Build the mutation body from the form. Required fields are always sent;
 * optional fields are OMITTED when blank rather than sent as empty/zero, so the
 * backend keeps its own defaults. NO `tenant_id` is ever added — scope is
 * decided by which credential the request carries.
 */
function buildMutationBody(form: OfferingFormState): OfferingMutation {
  const body: OfferingMutation = {
    provider_id: form.provider_id.trim(),
    upstream_model_id: form.upstream_model_id.trim(),
    enabled: form.enabled,
  };
  if (form.role !== "") body.role = form.role as OfferingMutation["role"];

  const numericFields: readonly (keyof OfferingMutation & ScalarFieldKey)[] = [
    "priority",
    "weight",
    "canary_percent",
    "shadow_percent",
    "context_window",
    "input_price_per_1m",
    "output_price_per_1m",
    "cached_input_price_per_1m",
    "cache_write_price_per_1m",
    "reasoning_price_per_1m",
    "audio_second_price_per_1m",
    "audio_character_price_per_1m",
  ];
  for (const field of numericFields) {
    const parsed = numOrUndefined(form[field]);
    if (parsed !== undefined) {
      (body as Record<string, unknown>)[field] = parsed;
    }
  }

  const capabilities = form.capabilities
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry !== "");
  if (capabilities.length > 0) body.capabilities = capabilities;

  if (form.region.trim() !== "") body.region = form.region.trim();
  if (form.currency.trim() !== "") body.currency = form.currency.trim();
  if (form.source.trim() !== "") body.source = form.source.trim();

  return body;
}

export default function ModelOfferingsPage() {
  const { modelId = "" } = useParams<{ modelId: string }>();
  const { t } = useI18n();
  const { toastError } = useOperatorError();
  // Slice 2a's scope machinery: the credential follows the active scope, and the
  // list keys on it so flipping the toggle refetches the other catalog.
  const apiKey = useCatalogApiKey();
  const { scope } = useCatalogScope();
  const queryClient = useQueryClient();
  const queryKey = useMemo(() => ["model-offerings", modelId, scope], [modelId, scope]);

  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<Offering | null>(null);
  const [form, setForm] = useState<OfferingFormState>(emptyForm);
  const [formError, setFormError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<Offering | null>(null);
  const newButtonRef = useRef<HTMLButtonElement>(null);

  const {
    data,
    isLoading,
    error: listError,
  } = useQuery({
    queryKey,
    queryFn: () =>
      adminGet(apiKey, "/admin/v1/models/{model_id}/offerings", {
        params: { model_id: modelId },
      }),
    enabled: modelId !== "",
  });

  const offerings = useMemo(() => data?.data ?? [], [data]);

  function openCreate() {
    setEditing(null);
    setForm(emptyForm());
    setFormError(null);
    setFormOpen(true);
  }

  function openEdit(offering: Offering) {
    setEditing(offering);
    setForm(formFromOffering(offering));
    setFormError(null);
    setFormOpen(true);
  }

  const createMutation = useMutation({
    mutationFn: (body: OfferingMutation) =>
      adminPost(apiKey, "/admin/v1/models/{model_id}/offerings", body, {
        params: { model_id: modelId },
      }),
    // The response carries `scope`: a platform-scope create is NOT assumed to be
    // platform — we report whichever catalog the backend actually wrote to.
    onSuccess: (response) => {
      queryClient.invalidateQueries({ queryKey });
      const written = response.offering?.scope ?? response.scope;
      toast.success(
        written
          ? t("page.modelOfferings.toast.createdScoped", { scope: written })
          : t("page.modelOfferings.toast.created"),
      );
      setFormOpen(false);
    },
    // Surface the backend message verbatim — including the adoption-gate 400
    // ("tenant_id is required for a platform operator" before the platform
    // catalog is adopted) — both inline and as a toast.
    onError: (error: Error) => {
      setFormError(error.message);
      toastError(error);
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, body }: { id: string; body: OfferingMutation }) =>
      adminPut(apiKey, "/admin/v1/models/{model_id}/offerings/{offering_id}", body, {
        params: { model_id: modelId, offering_id: id },
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey });
      toast.success(t("page.modelOfferings.toast.updated"));
      setFormOpen(false);
      setEditing(null);
    },
    onError: (error: Error) => {
      setFormError(error.message);
      toastError(error);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      adminDelete(apiKey, "/admin/v1/models/{model_id}/offerings/{offering_id}", {
        params: { model_id: modelId, offering_id: id },
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey });
      toast.success(t("page.modelOfferings.toast.deleted"));
      setDeleting(null);
    },
    onError: (error: Error) => {
      toastError(error);
      setDeleting(null);
    },
  });

  function submitForm() {
    setFormError(null);
    if (form.provider_id.trim() === "") {
      setFormError(t("page.modelOfferings.validation.providerRequired"));
      return;
    }
    if (form.upstream_model_id.trim() === "") {
      setFormError(t("page.modelOfferings.validation.upstreamRequired"));
      return;
    }
    const body = buildMutationBody(form);
    if (editing) {
      updateMutation.mutate({ id: String(editing.id), body });
    } else {
      createMutation.mutate(body);
    }
  }

  const updateField = (name: ScalarFieldKey, value: string) =>
    setForm((prev) => ({ ...prev, [name]: value }));

  const submitting = createMutation.isPending || updateMutation.isPending;

  function scopeLabel(rowScope: Offering["scope"]): string {
    if (rowScope === "platform") return t("catalog.scope.platform");
    if (rowScope === "tenant") return t("catalog.scope.tenant");
    return "—";
  }

  return (
    <div className="flex flex-col gap-4">
      <div>
        <Link to="/app/models" className="text-sm text-muted-foreground hover:underline">
          {t("page.modelOfferings.back")}
        </Link>
      </div>
      <div className="flex items-start justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold">{t("page.modelOfferings.title", { modelId })}</h1>
          <p className="text-sm text-muted-foreground">{t("page.modelOfferings.description")}</p>
          {scope === "platform" ? (
            <p className="mt-1 text-xs text-muted-foreground">{t("catalog.scope.hint")}</p>
          ) : null}
        </div>
        <div className="flex items-center gap-3">
          <CatalogScopeToggle />
          <Button ref={newButtonRef} onClick={openCreate}>
            {t("resource.action.new")}
          </Button>
        </div>
      </div>

      {listError ? (
        <p
          role="alert"
          className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
        >
          {t("page.modelOfferings.loadError", { message: listError.message })}
        </p>
      ) : null}

      <div className="overflow-x-auto rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t("page.modelOfferings.col.provider")}</TableHead>
              <TableHead>{t("page.modelOfferings.col.upstreamModel")}</TableHead>
              <TableHead>{t("page.modelOfferings.col.role")}</TableHead>
              <TableHead>{t("page.modelOfferings.col.priority")}</TableHead>
              <TableHead>{t("page.modelOfferings.col.enabled")}</TableHead>
              <TableHead>{t("page.modelOfferings.col.scope")}</TableHead>
              <TableHead className="w-32">
                <span className="sr-only">{t("resource.table.actionsColumn")}</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={7} className="h-24 text-center">
                  {t("resource.table.loading")}
                </TableCell>
              </TableRow>
            ) : offerings.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} className="h-24 text-center">
                  {t("page.modelOfferings.empty")}
                </TableCell>
              </TableRow>
            ) : (
              offerings.map((offering) => (
                <TableRow key={offering.id} data-testid={`offering-${offering.id}`}>
                  <TableCell className="font-medium">
                    {offering.provider ?? offering.provider_id}
                  </TableCell>
                  <TableCell className="font-mono text-xs">{offering.upstream_model_id}</TableCell>
                  <TableCell>{offering.role}</TableCell>
                  <TableCell>{str(offering.priority)}</TableCell>
                  <TableCell>{offering.enabled ? t("common.yes") : t("common.no")}</TableCell>
                  <TableCell>{scopeLabel(offering.scope)}</TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-2">
                      <Button variant="ghost" size="sm" onClick={() => openEdit(offering)}>
                        {t("resource.action.edit")}
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="text-destructive"
                        onClick={() => setDeleting(offering)}
                      >
                        {t("resource.action.delete")}
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      <Sheet open={formOpen} onOpenChange={setFormOpen}>
        <SheetContent className="overflow-y-auto sm:max-w-lg">
          <SheetHeader>
            <SheetTitle>
              {editing
                ? t("page.modelOfferings.edit.title")
                : t("page.modelOfferings.create.title")}
            </SheetTitle>
          </SheetHeader>
          <div className="grid gap-3 px-4 pb-4">
            {SCALAR_FIELDS.map((field) => (
              <div key={field.name} className="grid gap-1.5">
                <Label htmlFor={field.name}>
                  {t(field.labelKey)}
                  {field.required ? " *" : ""}
                </Label>
                <Input
                  id={field.name}
                  type={field.kind === "number" ? "number" : "text"}
                  value={form[field.name]}
                  onChange={(event) => updateField(field.name, event.target.value)}
                  placeholder={field.placeholderKey ? t(field.placeholderKey) : undefined}
                />
              </div>
            ))}
            <div className="grid gap-1.5">
              <Label htmlFor="role">{t("page.modelOfferings.field.role")}</Label>
              <Select
                value={form.role}
                onValueChange={(value) => setForm((prev) => ({ ...prev, role: value }))}
              >
                <SelectTrigger id="role">
                  <SelectValue placeholder={t("page.modelOfferings.field.role.placeholder")} />
                </SelectTrigger>
                <SelectContent>
                  {ROLE_OPTIONS.map((option) => (
                    <SelectItem key={option.value} value={option.value}>
                      {t(option.labelKey)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-center gap-2">
              <Switch
                id="enabled"
                checked={form.enabled}
                onCheckedChange={(checked) => setForm((prev) => ({ ...prev, enabled: checked }))}
              />
              <Label htmlFor="enabled">{t("page.modelOfferings.field.enabled")}</Label>
            </div>

            {formError ? (
              <p
                role="alert"
                className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
              >
                {formError}
              </p>
            ) : null}

            <div className="flex justify-end gap-2 pt-2">
              <Button variant="outline" onClick={() => setFormOpen(false)}>
                {t("resource.action.cancel")}
              </Button>
              <Button onClick={submitForm} disabled={submitting}>
                {editing ? t("resource.action.saveChanges") : t("resource.action.create")}
              </Button>
            </div>
          </div>
        </SheetContent>
      </Sheet>

      <AlertDialog open={deleting !== null} onOpenChange={(open) => !open && setDeleting(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t("page.modelOfferings.delete.title")}</AlertDialogTitle>
            <AlertDialogDescription>
              {t("page.modelOfferings.delete.description")}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("resource.action.cancel")}</AlertDialogCancel>
            <AlertDialogAction
              onClick={(event) => {
                event.preventDefault();
                if (deleting) deleteMutation.mutate(String(deleting.id));
              }}
            >
              {t("resource.action.delete")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
