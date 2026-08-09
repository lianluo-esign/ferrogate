import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { useCatalogScope } from "@/hooks/use-catalog-scope";
import { useI18n } from "@/i18n";

const TOGGLE_ID = "catalog-scope-toggle";

/**
 * Header control that swaps a catalog page between tenant and platform scope
 * (#912). It renders NOTHING for a session without platform access, so a
 * non-superadmin never sees (nor can toggle) platform scope — the gate is the
 * presence of the platform-operator credential, surfaced as
 * `canUsePlatform`.
 */
export function CatalogScopeToggle() {
  const { scope, setScope, canUsePlatform } = useCatalogScope();
  const { t } = useI18n();

  if (!canUsePlatform) return null;

  const isPlatform = scope === "platform";

  return (
    <div className="flex items-center gap-2">
      <Label htmlFor={TOGGLE_ID} className="text-sm text-muted-foreground">
        {t("catalog.scope.toggle")}
      </Label>
      <Switch
        id={TOGGLE_ID}
        checked={isPlatform}
        onCheckedChange={(checked) => setScope(checked ? "platform" : "tenant")}
        aria-label={t("catalog.scope.toggle")}
      />
      <span className="text-sm font-medium">
        {isPlatform ? t("catalog.scope.platform") : t("catalog.scope.tenant")}
      </span>
    </div>
  );
}
