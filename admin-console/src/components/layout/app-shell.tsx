import { Fragment, useEffect, useRef } from "react";
import { Link, Outlet, useLocation } from "react-router-dom";
import { AppSidebar } from "@/components/layout/app-sidebar";
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

export function AppShell() {
  const location = useLocation();
  const title = currentPageTitle(location.pathname);
  const pageContentRef = useRef<HTMLDivElement>(null);
  const shouldFocusMainHeading = Boolean(
    (location.state as { focusMainHeading?: boolean } | null)?.focusMainHeading,
  );

  useEffect(() => {
    if (!shouldFocusMainHeading) return;
    const frame = window.requestAnimationFrame(() => {
      const heading = pageContentRef.current?.querySelector<HTMLElement>("h1");
      if (!heading) return;
      heading.tabIndex = -1;
      heading.focus({ preventScroll: true });
    });
    return () => window.cancelAnimationFrame(frame);
  }, [location.key, shouldFocusMainHeading]);

  return (
    <SidebarProvider>
      <AppSidebar />
      <SidebarInset>
        <header className="flex h-16 shrink-0 items-center gap-2 border-b transition-[width,height] ease-linear">
          <div className="flex items-center gap-2 px-4">
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
        </header>
        <div ref={pageContentRef} className="flex flex-1 flex-col gap-4 p-4">
          <Outlet />
        </div>
      </SidebarInset>
    </SidebarProvider>
  );
}
