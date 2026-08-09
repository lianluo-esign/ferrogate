import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
// Accessible global language selector (#346).
//
// Mirrors `theme-switcher` (Radix dropdown + icon trigger) so auth pages and
// the protected shell share one interaction pattern. Each option is labelled
// with its autonym (`LOCALE_META.nativeName`), so a user can always find their
// language regardless of the currently active locale.
import { Languages } from "lucide-react";
import { LOCALES, LOCALE_META, isLocale } from "./catalog";
import { useI18n } from "./i18n-provider";

export function LanguageSwitcher() {
  const { locale, setLocale, t } = useI18n();
  const currentName = LOCALE_META[locale].nativeName;

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          type="button"
          variant="ghost"
          size="icon"
          aria-label={t("language.current", { name: currentName })}
          title={t("language.change")}
        >
          <Languages aria-hidden="true" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-40">
        <DropdownMenuLabel>{t("language.label")}</DropdownMenuLabel>
        <DropdownMenuRadioGroup
          value={locale}
          onValueChange={(value) => {
            if (isLocale(value)) setLocale(value);
          }}
        >
          {LOCALES.map((option) => (
            // Autonyms are not translated -> mark them so machine translation /
            // browser translators leave them intact.
            <DropdownMenuRadioItem key={option} value={option} translate="no" lang={option}>
              {LOCALE_META[option].nativeName}
            </DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
