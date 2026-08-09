import { AppSidebar } from "@/components/layout/app-sidebar";
import { findNavigationLeaf } from "@/components/layout/nav-config";
import { ThemeSwitcher } from "@/components/theme-switcher";
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";
import { Separator } from "@/components/ui/separator";
import { SidebarInset, SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { LanguageSwitcher, useI18n } from "@/i18n";
import type { TranslationKey } from "@/i18n";
import { Fragment, useEffect, useRef } from "react";
import { Link, Outlet, useLocation } from "react-router-dom";

function currentPageTitleKey(pathname: string): TranslationKey {
  return findNavigationLeaf(pathname)?.titleKey ?? "nav.dashboard";
}

function prepareMainHeading(container: HTMLElement | null) {
  const heading = container?.querySelector<HTMLElement>("h1") ?? null;
  if (!heading) return null;

  heading.id = "main-content";
  heading.tabIndex = -1;
  return heading;
}

export function AppShell() {
  const location = useLocation();
  const { t } = useI18n();
  const title = t(currentPageTitleKey(location.pathname));
  const pageContentRef = useRef<HTMLDivElement>(null);
  const shouldFocusMainHeading = Boolean(
    (location.state as { focusMainHeading?: boolean } | null)?.focusMainHeading,
  );

  // biome-ignore lint/correctness/useExhaustiveDependencies: location.key is an intentional trigger dependency so the heading-focus observer re-attaches on every navigation, including to the same pathname
  useEffect(() => {
    let preparedHeading: HTMLElement | null = null;
    const prepareAndFocus = () => {
      const heading = prepareMainHeading(pageContentRef.current);
      if (!heading || heading === preparedHeading) return;
      preparedHeading = heading;
      if (shouldFocusMainHeading) heading.focus({ preventScroll: true });
    };

    const content = pageContentRef.current;
    if (!content) return;

    const observer = new MutationObserver(prepareAndFocus);
    observer.observe(content, { childList: true, subtree: true });
    prepareAndFocus();
    return () => observer.disconnect();
  }, [location.key, shouldFocusMainHeading]);

  return (
    <SidebarProvider>
      {/* biome-ignore lint/a11y/useValidAnchor: genuine skip-to-content link — href="#main-content" is a real in-page fragment target, progressively enhanced with onClick focus management for the main heading */}
      <a
        href="#main-content"
        className="fixed left-3 top-3 z-[100] -translate-y-20 rounded-md bg-background px-3 py-2 text-sm font-medium shadow ring-2 ring-ring transition-transform focus:translate-y-0"
        onClick={(event) => {
          const heading = prepareMainHeading(pageContentRef.current);
          if (!heading) return;
          event.preventDefault();
          heading.focus();
          window.history.replaceState(null, "", "#main-content");
        }}
      >
        {t("shell.skipToContent")}
      </a>
      <AppSidebar />
      <SidebarInset>
        <header className="flex h-16 shrink-0 items-center gap-2 border-b transition-[width,height] ease-linear">
          <div className="flex min-w-0 items-center gap-2 px-4">
            <SidebarTrigger className="-ml-1" />
            <Separator orientation="vertical" className="mr-2 h-4" />
            <Breadcrumb>
              <BreadcrumbList>
                <BreadcrumbItem className="hidden md:block">
                  <BreadcrumbLink asChild>
                    <Link to="/app">{t("shell.breadcrumb.root")}</Link>
                  </BreadcrumbLink>
                </BreadcrumbItem>
                <Fragment>
                  <BreadcrumbSeparator className="hidden md:block" />
                  <BreadcrumbItem>
                    <BreadcrumbPage>{title}</BreadcrumbPage>
                  </BreadcrumbItem>
                </Fragment>
              </BreadcrumbList>
            </Breadcrumb>
          </div>
          <div className="ml-auto flex items-center gap-1 px-4">
            <LanguageSwitcher />
            <ThemeSwitcher />
          </div>
        </header>
        <div ref={pageContentRef} className="flex flex-1 flex-col gap-4 p-4">
          <Outlet />
        </div>
      </SidebarInset>
    </SidebarProvider>
  );
}
