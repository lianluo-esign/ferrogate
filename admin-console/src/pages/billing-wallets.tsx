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

function formatCredits(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  return value.toLocaleString();
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
  const apiKey = session!.gatewayApiKey;
  const queryClient = useQueryClient();
  const [delta, setDelta] = useState("");
  const [error, setError] = useState<string | null>(null);

  const parsed = parseIntStrict(delta);
  const validationError =
    delta.trim() === ""
      ? "Enter a credit delta."
      : parsed === null
        ? "Delta must be a whole number of credits."
        : parsed === 0
          ? "Delta must be non-zero."
          : null;

  const mutation = useMutation({
    mutationFn: (delta_credits: number) =>
      adminPost(apiKey, "/admin/v1/wallets/{tenant_id}/adjust", { delta_credits }, {
        params: { tenant_id: wallet.tenant_id },
      }),
    onSuccess: () => {
      toast.success("Wallet balance adjusted");
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
          <DialogTitle>Adjust wallet credits</DialogTitle>
          <DialogDescription>
            Atomically applies <code>balance_credits += delta</code> for tenant{" "}
            <span className="font-mono">{wallet.tenant_id}</span>. A positive delta
            grants credits, a negative delta claws them back. Platform-operator-only
            (#229): a non-operator caller receives a 403.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4">
          <div className="grid gap-2">
            <Label htmlFor="adjust-delta">Delta (credits)</Label>
            <Input
              id="adjust-delta"
              inputMode="numeric"
              placeholder="e.g. 100000 or -50000"
              value={delta}
              onChange={(event) => {
                setDelta(event.target.value);
                setError(null);
              }}
            />
            <p className="text-xs text-muted-foreground">
              Current balance {formatCredits(wallet.balance_credits)} →{" "}
              {parsed !== null && validationError === null
                ? formatCredits(wallet.balance_credits + parsed)
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
            Cancel
          </Button>
          <Button
            type="button"
            disabled={validationError !== null || mutation.isPending}
            onClick={() => parsed !== null && mutation.mutate(parsed)}
          >
            {mutation.isPending ? "Adjusting…" : "Apply adjustment"}
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
  const apiKey = session!.gatewayApiKey;
  const queryClient = useQueryClient();
  const [amount, setAmount] = useState("");
  const [paymentMethodId, setPaymentMethodId] = useState("");
  const [error, setError] = useState<string | null>(null);

  const parsed = parseIntStrict(amount);
  const validationError =
    amount.trim() === ""
      ? "Enter an amount in USD cents."
      : parsed === null
        ? "Amount must be a whole number of USD cents."
        : parsed < 1
          ? "Amount must be at least 1 cent."
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
        toast.success(`Charge captured (${result.provider_charge_id})`);
        queryClient.invalidateQueries({ queryKey: ["wallets"] });
        queryClient.invalidateQueries({ queryKey: ["wallet-ledger", wallet.tenant_id] });
        onClose();
      } else {
        const reason = result.decline_reason ?? "charge declined";
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
          <DialogTitle>Charge payment method</DialogTitle>
          <DialogDescription>
            Captures a payment against tenant{" "}
            <span className="font-mono">{wallet.tenant_id}</span> and credits the
            wallet. Leave the payment method blank to use the tenant default.
            Platform-operator-only (#229): a non-operator caller receives a 403.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4">
          <div className="grid gap-2">
            <Label htmlFor="charge-amount">Amount (USD cents)</Label>
            <Input
              id="charge-amount"
              inputMode="numeric"
              placeholder="e.g. 5000 for $50.00"
              value={amount}
              onChange={(event) => {
                setAmount(event.target.value);
                setError(null);
              }}
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="charge-pm">Payment method id (optional)</Label>
            <Input
              id="charge-pm"
              placeholder="tenant default when blank"
              value={paymentMethodId}
              onChange={(event) => setPaymentMethodId(event.target.value)}
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
            Cancel
          </Button>
          <Button
            type="button"
            disabled={validationError !== null || mutation.isPending}
            onClick={() => parsed !== null && mutation.mutate(parsed)}
          >
            {mutation.isPending ? "Charging…" : "Capture charge"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function WalletLedger({ tenantId }: { tenantId: string }) {
  const { session } = useAuth();
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
            <TableHead>When</TableHead>
            <TableHead>Model</TableHead>
            <TableHead>Provider</TableHead>
            <TableHead className="text-right">Credits</TableHead>
            <TableHead className="text-right">Wallet Δ</TableHead>
            <TableHead className="text-right">Balance after</TableHead>
            <TableHead>Request</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {isLoading ? (
            <TableRow>
              <TableCell colSpan={7} className="h-20 text-center">
                Loading ledger…
              </TableCell>
            </TableRow>
          ) : error ? (
            <TableRow>
              <TableCell colSpan={7} className="h-20 text-center text-destructive">
                Failed to load ledger: {(error as Error).message}
              </TableCell>
            </TableRow>
          ) : entries.length === 0 ? (
            <TableRow>
              <TableCell colSpan={7} className="h-20 text-center">
                No ledger entries for this tenant.
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
                  {entry.credits.toLocaleString()}
                </TableCell>
                <TableCell className="text-right text-xs">
                  {formatCredits(entry.wallet_delta_credits)}
                </TableCell>
                <TableCell className="text-right text-xs">
                  {formatCredits(entry.wallet_balance_after_credits)}
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
        <h1 className="text-lg font-semibold">Wallets</h1>
        <p className="text-sm text-muted-foreground">
          Prepaid-credit wallets per tenant. Balance only ever moves through the
          atomic adjust action or a settled charge — never a blind overwrite.
          Adjust and charge are platform-operator-only (#229/#232); a non-operator
          caller sees a 403.
        </p>
      </div>

      {error ? (
        <p role="alert" className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          Failed to load wallets: {(error as Error).message}
        </p>
      ) : null}

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Tenant</TableHead>
              <TableHead className="text-right">Balance (credits)</TableHead>
              <TableHead>Auto-recharge</TableHead>
              <TableHead>Dunning</TableHead>
              <TableHead>Updated</TableHead>
              <TableHead className="w-64" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={6} className="h-24 text-center">
                  Loading…
                </TableCell>
              </TableRow>
            ) : wallets.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="h-24 text-center">
                  No wallets provisioned.
                </TableCell>
              </TableRow>
            ) : (
              wallets.map((wallet) => (
                <TableRow key={wallet.tenant_id}>
                  <TableCell className="font-mono text-sm">
                    {wallet.tenant_id}
                  </TableCell>
                  <TableCell className="text-right font-medium">
                    {formatCredits(wallet.balance_credits)}
                  </TableCell>
                  <TableCell className="text-xs">
                    {wallet.auto_recharge_threshold_credits != null &&
                    wallet.auto_recharge_amount_credits != null
                      ? `≤ ${formatCredits(
                          wallet.auto_recharge_threshold_credits,
                        )} → +${formatCredits(wallet.auto_recharge_amount_credits)}`
                      : "off"}
                  </TableCell>
                  <TableCell>
                    {wallet.dunning ? (
                      <Badge variant="destructive">dunning</Badge>
                    ) : (
                      <Badge variant="secondary">ok</Badge>
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
                        {selectedTenant === wallet.tenant_id ? "Hide ledger" : "Ledger"}
                      </Button>
                      <Button
                        size="sm"
                        onClick={() => setAction({ wallet, kind: "adjust" })}
                      >
                        Adjust
                      </Button>
                      <Button
                        variant="secondary"
                        size="sm"
                        onClick={() => setAction({ wallet, kind: "charge" })}
                      >
                        Charge
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
              Ledger — <span className="font-mono">{selectedWallet.tenant_id}</span>
            </CardTitle>
            <CardDescription>
              Balance {formatCredits(selectedWallet.balance_credits)} credits. Every
              settled request debits the wallet; the entries below mirror those
              wallet deltas.
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
