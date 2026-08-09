import { NAV_DASHBOARD, type NavGroup, isPathActive } from "@/components/layout/nav-config";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import {
  SidebarGroup,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarMenuSub,
  SidebarMenuSubButton,
  SidebarMenuSubItem,
  useSidebar,
} from "@/components/ui/sidebar";
import { useI18n } from "@/i18n";
import { ChevronRight } from "lucide-react";
import { type MouseEvent, useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";

const FOCUS_MAIN_HEADING_STATE = { focusMainHeading: true } as const;

function shouldHandleNavigation(event: MouseEvent<HTMLAnchorElement>): boolean {
  return event.button === 0 && !event.metaKey && !event.ctrlKey && !event.shiftKey && !event.altKey;
}

function GroupNavigation({
  group,
  pathname,
  onNavigate,
}: {
  group: NavGroup;
  pathname: string;
  onNavigate: (event: MouseEvent<HTMLAnchorElement>) => void;
}) {
  const { t } = useI18n();
  const isActive = group.items.some((item) => isPathActive(pathname, item.url));
  const [open, setOpen] = useState(isActive);
  const groupTitle = t(group.titleKey);

  useEffect(() => {
    if (isActive) setOpen(true);
  }, [isActive]);

  return (
    <Collapsible asChild open={open} onOpenChange={setOpen} className="group/collapsible">
      <SidebarMenuItem>
        <CollapsibleTrigger asChild>
          <SidebarMenuButton tooltip={groupTitle} isActive={isActive}>
            <group.icon />
            <span>{groupTitle}</span>
            <ChevronRight className="ml-auto transition-transform duration-200 group-data-[state=open]/collapsible:rotate-90" />
          </SidebarMenuButton>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <SidebarMenuSub>
            {group.items.map((item) => (
              <SidebarMenuSubItem key={item.url}>
                <SidebarMenuSubButton asChild isActive={isPathActive(pathname, item.url)}>
                  <Link to={item.url} state={FOCUS_MAIN_HEADING_STATE} onClick={onNavigate}>
                    <span>{t(item.titleKey)}</span>
                  </Link>
                </SidebarMenuSubButton>
              </SidebarMenuSubItem>
            ))}
          </SidebarMenuSub>
        </CollapsibleContent>
      </SidebarMenuItem>
    </Collapsible>
  );
}

export function NavMain({ groups }: { groups: NavGroup[] }) {
  const location = useLocation();
  const { isMobile, setOpenMobile } = useSidebar();
  const { t } = useI18n();
  const dashboardTitle = t(NAV_DASHBOARD.titleKey);

  function handleNavigation(event: MouseEvent<HTMLAnchorElement>) {
    if (isMobile && shouldHandleNavigation(event)) setOpenMobile(false);
  }

  return (
    <SidebarGroup>
      <SidebarGroupLabel>{t("nav.controlPlane")}</SidebarGroupLabel>
      <SidebarMenu>
        <SidebarMenuItem>
          <SidebarMenuButton
            asChild
            tooltip={dashboardTitle}
            isActive={isPathActive(location.pathname, NAV_DASHBOARD.url)}
          >
            <Link
              to={NAV_DASHBOARD.url}
              state={FOCUS_MAIN_HEADING_STATE}
              onClick={handleNavigation}
            >
              <NAV_DASHBOARD.icon />
              <span>{dashboardTitle}</span>
            </Link>
          </SidebarMenuButton>
        </SidebarMenuItem>
        {groups.map((group) => (
          <GroupNavigation
            key={group.titleKey}
            group={group}
            pathname={location.pathname}
            onNavigate={handleNavigation}
          />
        ))}
      </SidebarMenu>
    </SidebarGroup>
  );
}
