import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { type TranslationKey, useI18n } from "@/i18n";
import { Monitor, Moon, Sun } from "lucide-react";
import { useTheme } from "next-themes";
const nn = <T,>(v: T): NonNullable<T> => v as NonNullable<T>;

const THEME_OPTIONS = [
  { value: "light", labelKey: "component.themeSwitcher.light", icon: Sun },
  { value: "dark", labelKey: "component.themeSwitcher.dark", icon: Moon },
  { value: "system", labelKey: "component.themeSwitcher.system", icon: Monitor },
] as const satisfies readonly {
  value: string;
  labelKey: TranslationKey;
  icon: typeof Sun;
}[];

type ThemeName = (typeof THEME_OPTIONS)[number]["value"];

function isThemeName(value: string | undefined): value is ThemeName {
  return THEME_OPTIONS.some((option) => option.value === value);
}

export function ThemeSwitcher() {
  const { t } = useI18n();
  const { theme, setTheme } = useTheme();
  const selectedTheme = isThemeName(theme) ? theme : "system";
  const selectedOption = nn(THEME_OPTIONS.find((option) => option.value === selectedTheme));
  const SelectedIcon = selectedOption.icon;

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          type="button"
          variant="ghost"
          size="icon"
          aria-label={t("component.themeSwitcher.trigger", {
            theme: t(selectedOption.labelKey),
          })}
          title={t("component.themeSwitcher.changeTheme")}
        >
          <SelectedIcon aria-hidden="true" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-40">
        <DropdownMenuLabel>{t("component.themeSwitcher.appearance")}</DropdownMenuLabel>
        <DropdownMenuRadioGroup
          value={selectedTheme}
          onValueChange={(value) => {
            if (isThemeName(value)) setTheme(value);
          }}
        >
          {THEME_OPTIONS.map((option) => (
            <DropdownMenuRadioItem key={option.value} value={option.value}>
              <option.icon aria-hidden="true" />
              <span>{t(option.labelKey)}</span>
            </DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
