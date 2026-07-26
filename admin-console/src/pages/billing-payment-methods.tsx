// Payment-methods ops surface (issue #319): list a tenant's stored payment
// methods (/admin/v1/payment-methods?tenant_id=…), register a new one (POST),
// and remove one (DELETE /admin/v1/payment-methods/{id}).
//
// Contract wrinkle: the gateway's list endpoint REQUIRES a `tenant_id` query
// parameter at runtime (a payment method's id alone doesn't reveal its tenant),
// but the generated OpenAPI contract omits that query param — so this one call
// widens the typed options to carry it. Every other call is fully typed.
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { EntityReferencePicker } from "@/components/resource/entity-reference-picker";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
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
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
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
import { useI18n } from "@/i18n";
import { useFormatUnix } from "@/hooks/use-format-unix";
import { useOperatorError } from "@/hooks/use-operator-error";
import { adminDelete, adminGet, adminPost, type AdminSchema } from "@/lib/gateway-client";
import { DISABLED_WHEN_STATUS_NOT_ACTIVE } from "@/lib/resource-config";

type AdminPaymentMethod = AdminSchema<"AdminPaymentMethod">;

function CreatePaymentMethodDialog({ tenantId }: { tenantId: string }) {
  const { session } = useAuth();
  const { t } = useI18n();
  const { toastError } = useOperatorError();
  const apiKey = session!.gatewayApiKey;
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [provider, setProvider] = useState("");
  const [customerId, setCustomerId] = useState("");
  const [methodId, setMethodId] = useState("");
  const [isDefault, setIsDefault] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const invalid =
    provider.trim() === "" || customerId.trim() === "" || methodId.trim() === "";

  const mutation = useMutation({
    mutationFn: () =>
      adminPost(apiKey, "/admin/v1/payment-methods", {
        tenant_id: tenantId,
        provider: provider.trim(),
        provider_customer_id: customerId.trim(),
        provider_payment_method_id: methodId.trim(),
        is_default: isDefault,
      }),
    onSuccess: () => {
      toast.success(t("page.billingPaymentMethods.toastRegistered"));
      queryClient.invalidateQueries({ queryKey: ["payment-methods", tenantId] });
      setOpen(false);
      setProvider("");
      setCustomerId("");
      setMethodId("");
      setIsDefault(false);
      setError(null);
    },
    onError: (err: Error) => {
      setError(err.message);
      toastError(err);
    },
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm">{t("page.billingPaymentMethods.register")}</Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t("page.billingPaymentMethods.register")}</DialogTitle>
          <DialogDescription>
            {t("page.billingPaymentMethods.dialogDescription", { tenant: tenantId })}
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4">
          <div className="grid gap-2">
            <Label htmlFor="pm-provider">
              {t("page.billingPaymentMethods.field.provider")}
            </Label>
            <Input
              id="pm-provider"
              placeholder={t("page.billingPaymentMethods.placeholder.provider")}
              value={provider}
              onChange={(event) => setProvider(event.target.value)}
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="pm-customer">
              {t("page.billingPaymentMethods.field.customer")}
            </Label>
            <Input
              id="pm-customer"
              placeholder={t("page.billingPaymentMethods.placeholder.customer")}
              value={customerId}
              onChange={(event) => setCustomerId(event.target.value)}
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="pm-method">
              {t("page.billingPaymentMethods.field.method")}
            </Label>
            <Input
              id="pm-method"
              placeholder={t("page.billingPaymentMethods.placeholder.method")}
              value={methodId}
              onChange={(event) => setMethodId(event.target.value)}
            />
          </div>
          <div className="flex items-center gap-2">
            <Checkbox
              id="pm-default"
              checked={isDefault}
              onCheckedChange={(checked) => setIsDefault(checked === true)}
            />
            <Label htmlFor="pm-default">
              {t("page.billingPaymentMethods.field.default")}
            </Label>
          </div>
          {error ? (
            <p role="alert" className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {error}
            </p>
          ) : null}
        </div>
        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => setOpen(false)}>
            {t("resource.action.cancel")}
          </Button>
          <Button
            type="button"
            disabled={invalid || mutation.isPending}
            onClick={() => mutation.mutate()}
          >
            {mutation.isPending
              ? t("page.billingPaymentMethods.registering")
              : t("page.billingPaymentMethods.registerSubmit")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function BillingPaymentMethodsPage() {
  const { session } = useAuth();
  const { t } = useI18n();
  const formatUnix = useFormatUnix("—");
  const { toastError } = useOperatorError();
  const apiKey = session!.gatewayApiKey;
  const queryClient = useQueryClient();

  const [tenantId, setTenantId] = useState<string | null>(null);
  const [pendingDelete, setPendingDelete] = useState<AdminPaymentMethod | null>(null);

  const { data, isLoading, error } = useQuery({
    queryKey: ["payment-methods", tenantId],
    enabled: tenantId !== null,
    queryFn: () =>
      adminGet(apiKey, "/admin/v1/payment-methods", {
        // Contract omits this query param, but the gateway requires it.
        query: { tenant_id: tenantId as string },
      } as never),
  });

  const methods = data?.data ?? [];

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      adminDelete(apiKey, "/admin/v1/payment-methods/{payment_method_id}", {
        params: { payment_method_id: id },
      }),
    onSuccess: () => {
      toast.success(t("page.billingPaymentMethods.toastDeleted"));
      queryClient.invalidateQueries({ queryKey: ["payment-methods", tenantId] });
      setPendingDelete(null);
    },
    onError: (err: Error) => {
      toastError(err);
      setPendingDelete(null);
    },
  });

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold">
          {t("page.billingPaymentMethods.title")}
        </h1>
        <p className="text-sm text-muted-foreground">
          {t("page.billingPaymentMethods.description")}
        </p>
      </div>

      <div className="flex items-end gap-2">
        <div className="grid w-72 gap-2">
          {/* #340: select the tenant account from the shared #337 registry
              instead of pasting a tenant id; selecting a tenant lists its stored
              methods (the canonical `id` drives the required tenant_id query and
              the register payload). */}
          <Label htmlFor="pm-tenant">{t("common.tenant")}</Label>
          <EntityReferencePicker
            id="pm-tenant"
            label={t("common.tenant")}
            reference={{
              target: "tenant-accounts",
              valueKey: "id",
              primaryLabelKey: "name",
              secondaryLabelKeys: ["slug"],
              // #340 box 5: a suspended tenant is marked and unselectable.
              disabledWhen: DISABLED_WHEN_STATUS_NOT_ACTIVE,
            }}
            value={tenantId ?? ""}
            dependencyValues={{}}
            placeholder={t("page.billingPaymentMethods.tenantIdPlaceholder")}
            onChange={(value) =>
              setTenantId(typeof value === "string" && value ? value : null)
            }
          />
        </div>
        {tenantId ? <CreatePaymentMethodDialog tenantId={tenantId} /> : null}
      </div>

      {error ? (
        <p role="alert" className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {t("page.billingPaymentMethods.loadError", {
            message: (error as Error).message,
          })}
        </p>
      ) : null}

      {tenantId === null ? (
        <p className="text-sm text-muted-foreground">
          {t("page.billingPaymentMethods.prompt")}
        </p>
      ) : (
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t("page.billingPaymentMethods.col.id")}</TableHead>
                <TableHead>{t("page.billingPaymentMethods.col.provider")}</TableHead>
                <TableHead>{t("page.billingPaymentMethods.col.customer")}</TableHead>
                <TableHead>{t("page.billingPaymentMethods.col.method")}</TableHead>
                <TableHead>{t("page.billingPaymentMethods.col.default")}</TableHead>
                <TableHead>{t("page.billingPaymentMethods.col.created")}</TableHead>
                <TableHead className="w-24" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading ? (
                <TableRow>
                  <TableCell colSpan={7} className="h-24 text-center">
                    {t("resource.table.loading")}
                  </TableCell>
                </TableRow>
              ) : methods.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="h-24 text-center">
                    {t("page.billingPaymentMethods.empty")}
                  </TableCell>
                </TableRow>
              ) : (
                methods.map((method) => (
                  <TableRow key={method.id}>
                    <TableCell className="font-mono text-xs">{method.id}</TableCell>
                    <TableCell className="text-sm">{method.provider}</TableCell>
                    <TableCell className="font-mono text-xs">
                      {method.provider_customer_id}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {method.provider_payment_method_id}
                    </TableCell>
                    <TableCell>
                      {method.is_default ? (
                        <Badge variant="secondary">
                          {t("page.billingPaymentMethods.badge.default")}
                        </Badge>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell className="text-xs">
                      {formatUnix(method.created_at_unix)}
                    </TableCell>
                    <TableCell>
                      <Button
                        variant="destructive"
                        size="sm"
                        onClick={() => setPendingDelete(method)}
                      >
                        {t("resource.action.delete")}
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      )}

      <AlertDialog
        open={pendingDelete !== null}
        onOpenChange={(open) => !open && setPendingDelete(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t("page.billingPaymentMethods.deleteTitle")}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t("page.billingPaymentMethods.deleteDescription", {
                id: pendingDelete?.id ?? "",
              })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("resource.action.cancel")}</AlertDialogCancel>
            <AlertDialogAction
              onClick={(event) => {
                event.preventDefault();
                if (pendingDelete) deleteMutation.mutate(pendingDelete.id);
              }}
            >
              {deleteMutation.isPending
                ? t("page.billingPaymentMethods.deleting")
                : t("resource.action.delete")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
