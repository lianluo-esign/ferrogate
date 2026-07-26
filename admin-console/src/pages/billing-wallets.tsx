// Wallet ops surface (issue #319): overview of every tenant's prepaid-credit
// wallet (/admin/v1/wallets), its ledger (/admin/v1/wallets/{tenant}/ledger),
// and the two platform-operator-only balance actions — adjust
// (/adjust, atomic `balance_credits += delta`) and charge
// (/charge, capture a payment method and credit the wallet).
//
// Operator-scope caveat (#229/#232): adjust/charge are platform-operator-only.
// The console cannot know the caller's scope for certain, so it always renders
// the actions (with an explicit operator-required note) and lets a gateway 403
// surface as a clear inline error + toast rather than pre-hiding the controls.
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { EntityReferencePicker } from "@/components/resource/entity-reference-picker";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useAuth } from "@/hooks/use-auth";
import { useI18n, type BoundFormatters } from "@/i18n";
import { adminGet, adminPost, type AdminSchema } from "@/lib/gateway-client";

type AdminWallet = AdminSchema<"AdminWallet">;

// The ledger endpoint is untyped in the contract (`object` w/ additionalProps),
// so the runtime `{ object: "list", data: LedgerEntry[] }` envelope is modeled
// locally over the ferrogate-billing `LedgerEntry` fields this view renders.
interface LedgerEntry {
  id: string;
  request_id: string;
  logical_model: string;
  provider: string;
  provider_model: string;
  credits: number;
  status_code: number;
  wallet_delta_credits: number | null;
  wallet_balance_after_credits: number | null;
  occurred_at_unix: number | null;
}

type WalletAction = "adjust" | "charge";

// Credits are integer counts, not currency: render through the locale number
// formatter (grouping only). Values are the API's exact representation and are
// never recomputed or rounded here.
function formatCredits(
  format: BoundFormatters,
  value: number | null | undefined,
): string {
  if (value === null || value === undefined) return "—";
  return format.number(value);
}

function formatUnix(unix: number | null | undefined): string {
  if (unix === null || unix === undefined) return "—";
  return new Date(unix * 1000).toLocaleString();
}

/** Parses a signed integer string; returns null when not a clean integer. */
function parseIntStrict(raw: string): number | null {
  const trimmed = raw.trim();
  if (!/^-?\d+$/.test(trimmed)) return null;
  const value = Number(trimmed);
  return Number.isSafeInteger(value) ? value : null;
}

function AdjustDialog({
  wallet,
  onClose,
}: {
  wallet: AdminWallet;
  onClose: () => void;
}) {
  const { session } = useAuth();
  const { t, format } = useI18n();
  const apiKey = session!.gatewayApiKey;
  const queryClient = useQueryClient();
  const [delta, setDelta] = useState("");
  const [error, setError] = useState<string | null>(null);

  const parsed = parseIntStrict(delta);
  const validationError =
    delta.trim() === ""
      ? t("page.billingWallets.adjust.enterDelta")
      : parsed === null
        ? t("page.billingWallets.adjust.deltaWhole")
        : parsed === 0
          ? t("page.billingWallets.adjust.deltaNonZero")
          : null;

  const mutation = useMutation({
    mutationFn: (delta_credits: number) =>
      adminPost(apiKey, "/admin/v1/wallets/{tenant_id}/adjust", { delta_credits }, {
        params: { tenant_id: wallet.tenant_id },
      }),
    onSuccess: () => {
      toast.success(t("page.billingWallets.adjust.toastSuccess"));
      queryClient.invalidateQueries({ queryKey: ["wallets"] });
      queryClient.invalidateQueries({ queryKey: ["wallet-ledger", wallet.tenant_id] });
      onClose();
    },
    onError: (err: Error) => {
      setError(err.message);
      toast.error(err.message);
    },
  });

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t("page.billingWallets.adjust.title")}</DialogTitle>
          <DialogDescription>
            {t("page.billingWallets.adjust.descriptionLead")}{" "}
            <code>balance_credits += delta</code>{" "}
            {t("page.billingWallets.adjust.descriptionTail", {
              tenant: wallet.tenant_id,
            })}
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4">
          <div className="grid gap-2">
            <Label htmlFor="adjust-delta">
              {t("page.billingWallets.adjust.deltaLabel")}
            </Label>
            <Input
              id="adjust-delta"
              inputMode="numeric"
              placeholder={t("page.billingWallets.adjust.deltaPlaceholder")}
              value={delta}
              onChange={(event) => {
                setDelta(event.target.value);
                setError(null);
              }}
            />
            <p className="text-xs text-muted-foreground">
              {t("page.billingWallets.adjust.currentBalance")}{" "}
              {formatCredits(format, wallet.balance_credits)} →{" "}
              {parsed !== null && validationError === null
                ? formatCredits(format, wallet.balance_credits + parsed)
                : "…"}
            </p>
          </div>
          {error ? (
            <p role="alert" className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {error}
            </p>
          ) : null}
        </div>
        <DialogFooter>
          <Button type="button" variant="outline" onClick={onClose}>
            {t("resource.action.cancel")}
          </Button>
          <Button
            type="button"
            disabled={validationError !== null || mutation.isPending}
            onClick={() => parsed !== null && mutation.mutate(parsed)}
          >
            {mutation.isPending
              ? t("page.billingWallets.adjust.applying")
              : t("page.billingWallets.adjust.submit")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ChargeDialog({
  wallet,
  onClose,
}: {
  wallet: AdminWallet;
  onClose: () => void;
}) {
  const { session } = useAuth();
  const { t } = useI18n();
  const apiKey = session!.gatewayApiKey;
  const queryClient = useQueryClient();
  const [amount, setAmount] = useState("");
  const [paymentMethodId, setPaymentMethodId] = useState("");
  const [error, setError] = useState<string | null>(null);

  const parsed = parseIntStrict(amount);
  const validationError =
    amount.trim() === ""
      ? t("page.billingWallets.charge.enterAmount")
      : parsed === null
        ? t("page.billingWallets.charge.amountWhole")
        : parsed < 1
          ? t("page.billingWallets.charge.amountMin")
          : null;

  const mutation = useMutation({
    mutationFn: (amount_usd_cents: number) =>
      adminPost(
        apiKey,
        "/admin/v1/wallets/{tenant_id}/charge",
        {
          amount_usd_cents,
          payment_method_id:
            paymentMethodId.trim() === "" ? null : paymentMethodId.trim(),
        },
        { params: { tenant_id: wallet.tenant_id } },
      ),
    onSuccess: (result) => {
      if (result.succeeded) {
        toast.success(
          t("page.billingWallets.charge.toastCaptured", {
            id: result.provider_charge_id,
          }),
        );
        queryClient.invalidateQueries({ queryKey: ["wallets"] });
        queryClient.invalidateQueries({ queryKey: ["wallet-ledger", wallet.tenant_id] });
        onClose();
      } else {
        const reason =
          result.decline_reason ?? t("page.billingWallets.charge.declineDefault");
        setError(reason);
        toast.error(reason);
      }
    },
    onError: (err: Error) => {
      setError(err.message);
      toast.error(err.message);
    },
  });

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t("page.billingWallets.charge.title")}</DialogTitle>
          <DialogDescription>
            {t("page.billingWallets.charge.description", {
              tenant: wallet.tenant_id,
            })}
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4">
          <div className="grid gap-2">
            <Label htmlFor="charge-amount">
              {t("page.billingWallets.charge.amountLabel")}
            </Label>
            <Input
              id="charge-amount"
              inputMode="numeric"
              placeholder={t("page.billingWallets.charge.amountPlaceholder")}
              value={amount}
              onChange={(event) => {
                setAmount(event.target.value);
                setError(null);
              }}
            />
          </div>
          <div className="grid gap-2">
            {/* #340: choose one of the tenant's registered payment methods from
                the shared #337 registry rather than pasting a method id. The
                picker is scoped to this wallet's tenant, so only that tenant's
                methods are selectable; leaving it blank charges the tenant
                default. The stored method's canonical `id` is submitted. */}
            <Label htmlFor="charge-pm">
              {t("page.billingWallets.charge.pmLabel")}
            </Label>
            <EntityReferencePicker
              id="charge-pm"
              label={t("page.billingWallets.charge.pmLabel")}
              reference={{
                target: "payment-methods",
                valueKey: "id",
                // #340 review follow-up: `provider` was the primary label, so
                // every method of a tenant rendered as the same word ("stripe")
                // and only the secondary line told them apart. AdminPaymentMethod
                // carries no operator-chosen name, so the provider's own method
                // handle is the sole distinguishing label; it is a non-secret
                // reference token (already displayed on this page's table) and it
                // is still not what gets submitted -- the canonical `id` is.
                primaryLabelKey: "provider_payment_method_id",
                secondaryLabelKeys: ["provider", "provider_customer_id"],
                dependencies: [{ field: "tenant_id", queryKey: "tenant_id" }],
              }}
              value={paymentMethodId}
              dependencyValues={{ tenant_id: wallet.tenant_id }}
              placeholder={t("page.billingWallets.charge.pmPlaceholder")}
              onChange={(value) =>
                setPaymentMethodId(typeof value === "string" ? value : "")
              }
            />
          </div>
          {error ? (
            <p role="alert" className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {error}
            </p>
          ) : null}
        </div>
        <DialogFooter>
          <Button type="button" variant="outline" onClick={onClose}>
            {t("resource.action.cancel")}
          </Button>
          <Button
            type="button"
            disabled={validationError !== null || mutation.isPending}
            onClick={() => parsed !== null && mutation.mutate(parsed)}
          >
            {mutation.isPending
              ? t("page.billingWallets.charge.charging")
              : t("page.billingWallets.charge.submit")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function WalletLedger({ tenantId }: { tenantId: string }) {
  const { session } = useAuth();
  const { t, format } = useI18n();
  const apiKey = session!.gatewayApiKey;

  const { data, isLoading, error } = useQuery({
    queryKey: ["wallet-ledger", tenantId],
    queryFn: async () => {
      const body = await adminGet(apiKey, "/admin/v1/wallets/{tenant_id}/ledger", {
        params: { tenant_id: tenantId },
      });
      return (body as { data?: LedgerEntry[] }).data ?? [];
    },
  });

  const entries = data ?? [];

  return (
    <div className="rounded-md border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>{t("page.billingWallets.ledger.col.when")}</TableHead>
            <TableHead>{t("page.billingWallets.ledger.col.model")}</TableHead>
            <TableHead>{t("page.billingWallets.ledger.col.provider")}</TableHead>
            <TableHead className="text-right">
              {t("page.billingWallets.ledger.col.credits")}
            </TableHead>
            <TableHead className="text-right">
              {t("page.billingWallets.ledger.col.walletDelta")}
            </TableHead>
            <TableHead className="text-right">
              {t("page.billingWallets.ledger.col.balanceAfter")}
            </TableHead>
            <TableHead>{t("page.billingWallets.ledger.col.request")}</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {isLoading ? (
            <TableRow>
              <TableCell colSpan={7} className="h-20 text-center">
                {t("page.billingWallets.ledger.loading")}
              </TableCell>
            </TableRow>
          ) : error ? (
            <TableRow>
              <TableCell colSpan={7} className="h-20 text-center text-destructive">
                {t("page.billingWallets.ledger.loadError", {
                  message: (error as Error).message,
                })}
              </TableCell>
            </TableRow>
          ) : entries.length === 0 ? (
            <TableRow>
              <TableCell colSpan={7} className="h-20 text-center">
                {t("page.billingWallets.ledger.empty")}
              </TableCell>
            </TableRow>
          ) : (
            entries.map((entry) => (
              <TableRow key={entry.id}>
                <TableCell className="text-xs">
                  {formatUnix(entry.occurred_at_unix)}
                </TableCell>
                <TableCell className="text-xs font-medium">
                  {entry.logical_model}
                </TableCell>
                <TableCell className="text-xs">
                  {entry.provider}/{entry.provider_model}
                </TableCell>
                <TableCell className="text-right text-xs">
                  {format.number(entry.credits)}
                </TableCell>
                <TableCell className="text-right text-xs">
                  {formatCredits(format, entry.wallet_delta_credits)}
                </TableCell>
                <TableCell className="text-right text-xs">
                  {formatCredits(format, entry.wallet_balance_after_credits)}
                </TableCell>
                <TableCell className="font-mono text-xs">{entry.request_id}</TableCell>
              </TableRow>
            ))
          )}
        </TableBody>
      </Table>
    </div>
  );
}

export default function BillingWalletsPage() {
  const { session } = useAuth();
  const { t, format } = useI18n();
  const apiKey = session!.gatewayApiKey;

  const [selectedTenant, setSelectedTenant] = useState<string | null>(null);
  const [action, setAction] = useState<{ wallet: AdminWallet; kind: WalletAction } | null>(
    null,
  );

  const { data, isLoading, error } = useQuery({
    queryKey: ["wallets"],
    queryFn: () => adminGet(apiKey, "/admin/v1/wallets"),
  });

  const wallets = useMemo(() => data?.data ?? [], [data]);
  const selectedWallet = useMemo(
    () => wallets.find((wallet) => wallet.tenant_id === selectedTenant) ?? null,
    [wallets, selectedTenant],
  );

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold">{t("page.billingWallets.title")}</h1>
        <p className="text-sm text-muted-foreground">
          {t("page.billingWallets.description")}
        </p>
      </div>

      {error ? (
        <p role="alert" className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {t("page.billingWallets.loadError", { message: (error as Error).message })}
        </p>
      ) : null}

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t("common.tenant")}</TableHead>
              <TableHead className="text-right">
                {t("page.billingWallets.col.balance")}
              </TableHead>
              <TableHead>{t("page.billingWallets.col.autoRecharge")}</TableHead>
              <TableHead>{t("page.billingWallets.col.dunning")}</TableHead>
              <TableHead>{t("page.billingWallets.col.updated")}</TableHead>
              <TableHead className="w-64" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={6} className="h-24 text-center">
                  {t("resource.table.loading")}
                </TableCell>
              </TableRow>
            ) : wallets.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="h-24 text-center">
                  {t("page.billingWallets.empty")}
                </TableCell>
              </TableRow>
            ) : (
              wallets.map((wallet) => (
                <TableRow key={wallet.tenant_id}>
                  <TableCell className="font-mono text-sm">
                    {wallet.tenant_id}
                  </TableCell>
                  <TableCell className="text-right font-medium">
                    {formatCredits(format, wallet.balance_credits)}
                  </TableCell>
                  <TableCell className="text-xs">
                    {wallet.auto_recharge_threshold_credits != null &&
                    wallet.auto_recharge_amount_credits != null
                      ? `≤ ${formatCredits(
                          format,
                          wallet.auto_recharge_threshold_credits,
                        )} → +${formatCredits(
                          format,
                          wallet.auto_recharge_amount_credits,
                        )}`
                      : t("page.billingWallets.autoRechargeOff")}
                  </TableCell>
                  <TableCell>
                    {wallet.dunning ? (
                      <Badge variant="destructive">
                        {t("page.billingWallets.badge.dunning")}
                      </Badge>
                    ) : (
                      <Badge variant="secondary">
                        {t("page.billingWallets.badge.ok")}
                      </Badge>
                    )}
                  </TableCell>
                  <TableCell className="text-xs">
                    {formatUnix(wallet.updated_at_unix)}
                  </TableCell>
                  <TableCell>
                    <div className="flex justify-end gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() =>
                          setSelectedTenant((current) =>
                            current === wallet.tenant_id ? null : wallet.tenant_id,
                          )
                        }
                      >
                        {selectedTenant === wallet.tenant_id
                          ? t("page.billingWallets.action.hideLedger")
                          : t("page.billingWallets.action.ledger")}
                      </Button>
                      <Button
                        size="sm"
                        onClick={() => setAction({ wallet, kind: "adjust" })}
                      >
                        {t("page.billingWallets.action.adjust")}
                      </Button>
                      <Button
                        variant="secondary"
                        size="sm"
                        onClick={() => setAction({ wallet, kind: "charge" })}
                      >
                        {t("page.billingWallets.action.charge")}
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      {selectedWallet ? (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">
              {t("page.billingWallets.ledger.cardTitle")} —{" "}
              <span className="font-mono">{selectedWallet.tenant_id}</span>
            </CardTitle>
            <CardDescription>
              {t("page.billingWallets.ledger.description", {
                balance: formatCredits(format, selectedWallet.balance_credits),
              })}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <WalletLedger tenantId={selectedWallet.tenant_id} />
          </CardContent>
        </Card>
      ) : null}

      {action?.kind === "adjust" ? (
        <AdjustDialog wallet={action.wallet} onClose={() => setAction(null)} />
      ) : null}
      {action?.kind === "charge" ? (
        <ChargeDialog wallet={action.wallet} onClose={() => setAction(null)} />
      ) : null}
    </div>
  );
}
