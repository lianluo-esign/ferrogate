import { useEffect, type ReactNode } from "react";
import {
  ThemeProvider as NextThemesProvider,
  useTheme,
} from "next-themes";

export const THEME_STORAGE_KEY = "ferrogate-admin-theme-v1";

const THEME_COLORS = {
  light: "#ffffff",
  dark: "#09090b",
} as const;

function ThemeDocumentMetadata() {
  const { resolvedTheme } = useTheme();

  useEffect(() => {
    if (resolvedTheme !== "light" && resolvedTheme !== "dark") return;

    const root = document.documentElement;
    root.style.colorScheme = resolvedTheme;

    let themeColor = document.querySelector<HTMLMetaElement>('meta[name="theme-color"]');
    if (!themeColor) {
      themeColor = document.createElement("meta");
      themeColor.name = "theme-color";
      document.head.appendChild(themeColor);
    }
    themeColor.content = THEME_COLORS[resolvedTheme];
  }, [resolvedTheme]);

  return null;
}

export function AppThemeProvider({ children }: { children: ReactNode }) {
  return (
    <NextThemesProvider
      attribute="class"
      defaultTheme="system"
      enableColorScheme
      enableSystem
      disableTransitionOnChange
      storageKey={THEME_STORAGE_KEY}
    >
      <ThemeDocumentMetadata />
      {children}
    </NextThemesProvider>
  );
}
