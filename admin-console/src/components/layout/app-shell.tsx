import { Fragment, useEffect, useRef } from "react";
import { Link, Outlet, useLocation } from "react-router-dom";
import { AppSidebar } from "@/components/layout/app-sidebar";
import { ThemeSwitcher } from "@/components/theme-switcher";
import { LanguageSwitcher } from "@/i18n";
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";
import { Separator } from "@/components/ui/separator";
import {
  SidebarInset,
  SidebarProvider,
  SidebarTrigger,
} from "@/components/ui/sidebar";
import { findNavigationLeaf } from "@/components/layout/nav-config";

function currentPageTitle(pathname: string): string {
  return findNavigationLeaf(pathname)?.title ?? "Dashboard";
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
  const title = currentPageTitle(location.pathname);
  const pageContentRef = useRef<HTMLDivElement>(null);
  const shouldFocusMainHeading = Boolean(
    (location.state as { focusMainHeading?: boolean } | null)?.focusMainHeading,
  );

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
        Skip to main content
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
                    <Link to="/app">FerroGate Admin</Link>
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
