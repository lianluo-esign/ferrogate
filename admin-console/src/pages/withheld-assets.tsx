// Withheld-assets operator surface (issue #379): the console view over
// GET /v1/assets/withheld — the operator-only inverse of GET /v1/assets that
// lists the pending_scan / quarantined asset versions the ordinary
// list/manifest/resolution paths hide from consumers (#366).
//
// From a row the operator acts via POST /v1/assets/{type}/{name}/{version}/
// visibility (#378): a completed out-of-band scan either promotes a
// pending_scan asset to visible (clean verdict) or quarantines it (flagged
// verdict). That transition is a fail-closed compare-and-swap on the server —
// an already-terminal asset returns 409 and a missing one 404 — so the confirm
// dialog surfaces those verdicts verbatim rather than optimistically mutating.
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
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
import { Textarea } from "@/components/ui/textarea";
import { useAuth } from "@/hooks/use-auth";
import { useI18n, type TranslationKey } from "@/i18n";
import { adminGet, adminPost, type AdminSchema } from "@/lib/gateway-client";
import { ApiError } from "@/types/auth";

type WithheldAsset = AdminSchema<"WithheldAssetSummary">;
type Visibility = WithheldAsset["visibility"];
type PromotionRequest = AdminSchema<"AssetVisibilityPromotionRequest">;

/** Operator intent -> the terminal `scan_outcome` recorded on the asset row. */
type Intent = "promote" | "quarantine";
const INTENT_SCAN_OUTCOME: Record<Intent, PromotionRequest["scan_outcome"]> = {
  promote: "clean",
  quarantine: "quarantined",
};

const PAGE_SIZE = 20;
const ALL_TYPES = "__all__";

// The asset-type filter mirrors the built-in families the push form offers; the
// labels resolve through `t()` at render so the picker localizes.
const ASSET_TYPE_FILTERS: { value: string; labelKey: TranslationKey }[] = [
  { value: "cli_tool", labelKey: "page.assets.type.cliTool" },
  { value: "mcp_manifest", labelKey: "page.assets.type.mcpManifest" },
  { value: "skill_bundle", labelKey: "page.assets.type.skillBundle" },
  { value: "static_site", labelKey: "page.assets.type.staticSite" },
  { value: "config_file", labelKey: "page.assets.type.configFile" },
];

function assetLabel(asset: WithheldAsset): string {
  return `${asset.asset_type}/${asset.name}@${asset.version}`;
}

function VisibilityBadge({ visibility }: { visibility: Visibility }) {
  const { t } = useI18n();
  return visibility === "quarantined" ? (
    <Badge variant="destructive">
      {t("page.withheldAssets.visibility.quarantined")}
    </Badge>
  ) : (
    <Badge variant="secondary">
      {t("page.withheldAssets.visibility.pendingScan")}
    </Badge>
  );
}

function EvidenceDialog({
  asset,
  onClose,
}: {
  asset: WithheldAsset | null;
  onClose: () => void;
}) {
  const { t } = useI18n();
  return (
    <Dialog open={asset !== null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-2xl">
        {asset ? (
          <>
            <DialogHeader>
              <DialogTitle>
                {t("page.withheldAssets.evidence.dialogTitle")}
              </DialogTitle>
              <DialogDescription>
                {t("page.withheldAssets.evidence.dialogDescription", {
                  asset: assetLabel(asset),
                })}
              </DialogDescription>
            </DialogHeader>
            <code className="whitespace-pre-wrap break-all rounded-md bg-muted px-3 py-2 font-mono text-xs">
              {asset.screening_evidence ??
                t("page.withheldAssets.evidence.none")}
            </code>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={onClose}>
                {t("common.close")}
              </Button>
            </DialogFooter>
          </>
        ) : null}
      </DialogContent>
    </Dialog>
  );
}

/** Maps an Admin API failure to localized, verdict-specific operator copy. */
function decisionErrorMessage(
  t: ReturnType<typeof useI18n>["t"],
  error: unknown,
): string {
  if (error instanceof ApiError) {
    if (error.status === 404) return t("page.withheldAssets.error.notFound");
    if (error.status === 409) return t("page.withheldAssets.error.conflict");
    if (error.status === 400)
      return t("page.withheldAssets.error.badRequest", {
        message: error.message,
      });
    return t("page.withheldAssets.error.generic", { message: error.message });
  }
  const message = error instanceof Error ? error.message : String(error);
  return t("page.withheldAssets.error.generic", { message });
}

export default function WithheldAssetsPage() {
  const { session } = useAuth();
  const { t, format } = useI18n();
  const apiKey = session!.gatewayApiKey;
  const queryClient = useQueryClient();

  const [assetType, setAssetType] = useState(ALL_TYPES);
  const [search, setSearch] = useState("");
  const [offset, setOffset] = useState(0);

  const [evidenceAsset, setEvidenceAsset] = useState<WithheldAsset | null>(null);
  const [pending, setPending] = useState<{
    asset: WithheldAsset;
    intent: Intent;
  } | null>(null);
  const [evidence, setEvidence] = useState("");
  const [decisionError, setDecisionError] = useState<string | null>(null);

  const query = useMemo(
    () => ({
      ...(assetType === ALL_TYPES ? {} : { asset_type: assetType }),
      ...(search.trim() === "" ? {} : { search: search.trim() }),
      offset,
      limit: PAGE_SIZE,
    }),
    [assetType, search, offset],
  );

  const queryKey = useMemo(
    () => ["withheld-assets", query] as const,
    [query],
  );

  const { data, isLoading, error: listError } = useQuery({
    queryKey,
    queryFn: () => adminGet(apiKey, "/v1/assets/withheld", { query }),
  });

  const rows = useMemo(() => data?.data ?? [], [data]);
  const total = data?.total ?? rows.length;

  const decisionMutation = useMutation({
    mutationFn: ({
      asset,
      intent,
    }: {
      asset: WithheldAsset;
      intent: Intent;
    }) => {
      const body: PromotionRequest = {
        scan_outcome: INTENT_SCAN_OUTCOME[intent],
        evidence: evidence.trim(),
      };
      return adminPost(
        apiKey,
        "/v1/assets/{asset_type}/{name}/{version}/visibility",
        body,
        {
          params: {
            asset_type: asset.asset_type,
            name: asset.name,
            version: asset.version,
          },
        },
      );
    },
    onSuccess: (_result, variables) => {
      toast.success(
        variables.intent === "promote"
          ? t("page.withheldAssets.promote.success")
          : t("page.withheldAssets.quarantine.success"),
      );
      closeDecision();
      queryClient.invalidateQueries({ queryKey: ["withheld-assets"] });
    },
    onError: (error: unknown) => {
      // Keep the dialog open on a 404/409 so the operator sees the exact
      // fail-closed verdict; refresh the list because the row's true state
      // just changed underneath them.
      const message = decisionErrorMessage(t, error);
      setDecisionError(message);
      toast.error(message);
      queryClient.invalidateQueries({ queryKey: ["withheld-assets"] });
    },
  });

  function openDecision(asset: WithheldAsset, intent: Intent) {
    setPending({ asset, intent });
    setEvidence("");
    setDecisionError(null);
  }

  function closeDecision() {
    setPending(null);
    setEvidence("");
    setDecisionError(null);
  }

  function submitDecision() {
    if (!pending) return;
    if (evidence.trim() === "") {
      setDecisionError(t("page.withheldAssets.error.evidenceRequired"));
      return;
    }
    decisionMutation.mutate(pending);
  }

  const from = rows.length === 0 ? 0 : offset + 1;
  const to = offset + rows.length;
  const canPrevious = offset > 0;
  const canNext = offset + rows.length < total;

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold">
          {t("page.withheldAssets.title")}
        </h1>
        <p className="text-sm text-muted-foreground">
          {t("page.withheldAssets.description")}
        </p>
      </div>

      <div className="flex flex-wrap items-end gap-4">
        <div className="grid gap-2">
          <Label htmlFor="withheld-asset-type">
            {t("page.withheldAssets.filter.assetType")}
          </Label>
          <Select
            value={assetType}
            onValueChange={(value) => {
              setAssetType(value);
              setOffset(0);
            }}
          >
            <SelectTrigger id="withheld-asset-type" className="w-48">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ALL_TYPES}>
                {t("page.withheldAssets.filter.allTypes")}
              </SelectItem>
              {ASSET_TYPE_FILTERS.map((option) => (
                <SelectItem key={option.value} value={option.value}>
                  {t(option.labelKey)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="grid gap-2">
          <Label htmlFor="withheld-search">
            {t("page.withheldAssets.filter.search")}
          </Label>
          <Input
            id="withheld-search"
            className="w-64"
            value={search}
            onChange={(event) => {
              setSearch(event.target.value);
              setOffset(0);
            }}
          />
        </div>
      </div>

      {listError ? (
        <p
          role="alert"
          className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
        >
          {t("page.withheldAssets.list.error", { message: listError.message })}
        </p>
      ) : null}

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t("page.withheldAssets.col.type")}</TableHead>
              <TableHead>{t("page.withheldAssets.col.name")}</TableHead>
              <TableHead>{t("page.withheldAssets.col.version")}</TableHead>
              <TableHead>{t("page.withheldAssets.col.visibility")}</TableHead>
              <TableHead>{t("page.withheldAssets.col.size")}</TableHead>
              <TableHead>{t("page.withheldAssets.col.evidence")}</TableHead>
              <TableHead className="w-44" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={7} className="h-24 text-center">
                  {t("resource.table.loading")}
                </TableCell>
              </TableRow>
            ) : rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} className="h-24 text-center">
                  {t("page.withheldAssets.empty")}
                </TableCell>
              </TableRow>
            ) : (
              rows.map((asset) => (
                <TableRow key={asset.id}>
                  <TableCell>{asset.asset_type}</TableCell>
                  <TableCell>{asset.name}</TableCell>
                  <TableCell>{asset.version}</TableCell>
                  <TableCell>
                    <VisibilityBadge visibility={asset.visibility} />
                  </TableCell>
                  <TableCell>{format.bytes(asset.size_bytes)}</TableCell>
                  <TableCell>
                    {asset.screening_evidence ? (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setEvidenceAsset(asset)}
                      >
                        {t("page.withheldAssets.evidence.view")}
                      </Button>
                    ) : (
                      <span className="text-sm text-muted-foreground">
                        {t("page.withheldAssets.evidence.none")}
                      </span>
                    )}
                  </TableCell>
                  <TableCell className="flex gap-2">
                    <Button
                      variant="default"
                      size="sm"
                      onClick={() => openDecision(asset, "promote")}
                    >
                      {t("page.withheldAssets.action.promote")}
                    </Button>
                    <Button
                      variant="destructive"
                      size="sm"
                      onClick={() => openDecision(asset, "quarantine")}
                    >
                      {t("page.withheldAssets.action.quarantine")}
                    </Button>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          {t("page.withheldAssets.pagination.summary", { from, to, total })}
        </p>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            disabled={!canPrevious}
            onClick={() => setOffset((current) => Math.max(0, current - PAGE_SIZE))}
          >
            {t("page.withheldAssets.pagination.previous")}
          </Button>
          <Button
            variant="outline"
            size="sm"
            disabled={!canNext}
            onClick={() => setOffset((current) => current + PAGE_SIZE)}
          >
            {t("page.withheldAssets.pagination.next")}
          </Button>
        </div>
      </div>

      <EvidenceDialog
        asset={evidenceAsset}
        onClose={() => setEvidenceAsset(null)}
      />

      <Dialog
        open={pending !== null}
        onOpenChange={(open) => !open && closeDecision()}
      >
        <DialogContent className="sm:max-w-lg">
          {pending ? (
            <>
              <DialogHeader>
                <DialogTitle>
                  {pending.intent === "promote"
                    ? t("page.withheldAssets.promote.title")
                    : t("page.withheldAssets.quarantine.title")}
                </DialogTitle>
                <DialogDescription>
                  {pending.intent === "promote"
                    ? t("page.withheldAssets.promote.description", {
                        asset: assetLabel(pending.asset),
                      })
                    : t("page.withheldAssets.quarantine.description", {
                        asset: assetLabel(pending.asset),
                      })}
                </DialogDescription>
              </DialogHeader>
              <div className="grid gap-4">
                <div className="grid gap-2">
                  <Label htmlFor="withheld-evidence">
                    {t("page.withheldAssets.field.evidence")}
                  </Label>
                  <Textarea
                    id="withheld-evidence"
                    value={evidence}
                    onChange={(event) => setEvidence(event.target.value)}
                    placeholder={t(
                      "page.withheldAssets.field.evidencePlaceholder",
                    )}
                    rows={3}
                  />
                </div>
                {decisionError ? (
                  <p
                    role="alert"
                    className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
                  >
                    {decisionError}
                  </p>
                ) : null}
              </div>
              <DialogFooter>
                <Button type="button" variant="outline" onClick={closeDecision}>
                  {t("common.cancel")}
                </Button>
                <Button
                  type="button"
                  variant={
                    pending.intent === "quarantine" ? "destructive" : "default"
                  }
                  disabled={decisionMutation.isPending}
                  onClick={submitDecision}
                >
                  {decisionMutation.isPending
                    ? t("page.withheldAssets.submitting")
                    : pending.intent === "promote"
                      ? t("page.withheldAssets.action.promote")
                      : t("page.withheldAssets.action.quarantine")}
                </Button>
              </DialogFooter>
            </>
          ) : null}
        </DialogContent>
      </Dialog>
    </div>
  );
}
