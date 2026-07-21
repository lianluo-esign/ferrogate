import { useEffect, useState, type MouseEvent } from "react";
import { ChevronRight } from "lucide-react";
import { Link, useLocation } from "react-router-dom";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
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
import {
  isPathActive,
  NAV_DASHBOARD,
  type NavGroup,
} from "@/components/layout/nav-config";

const FOCUS_MAIN_HEADING_STATE = { focusMainHeading: true } as const;

function shouldHandleNavigation(event: MouseEvent<HTMLAnchorElement>): boolean {
  return (
    event.button === 0 &&
    !event.metaKey &&
    !event.ctrlKey &&
    !event.shiftKey &&
    !event.altKey
  );
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
  const isActive = group.items.some((item) => isPathActive(pathname, item.url));
  const [open, setOpen] = useState(isActive);

  useEffect(() => {
    if (isActive) setOpen(true);
  }, [isActive]);

  return (
    <Collapsible
      asChild
      open={open}
      onOpenChange={setOpen}
      className="group/collapsible"
    >
      <SidebarMenuItem>
        <CollapsibleTrigger asChild>
          <SidebarMenuButton tooltip={group.title} isActive={isActive}>
            <group.icon />
            <span>{group.title}</span>
            <ChevronRight className="ml-auto transition-transform duration-200 group-data-[state=open]/collapsible:rotate-90" />
          </SidebarMenuButton>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <SidebarMenuSub>
            {group.items.map((item) => (
              <SidebarMenuSubItem key={item.url}>
                <SidebarMenuSubButton
                  asChild
                  isActive={isPathActive(pathname, item.url)}
                >
                  <Link
                    to={item.url}
                    state={FOCUS_MAIN_HEADING_STATE}
                    onClick={onNavigate}
                  >
                    <span>{item.title}</span>
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

  function handleNavigation(event: MouseEvent<HTMLAnchorElement>) {
    if (isMobile && shouldHandleNavigation(event)) setOpenMobile(false);
  }

  return (
    <SidebarGroup>
      <SidebarGroupLabel>Control Plane</SidebarGroupLabel>
      <SidebarMenu>
        <SidebarMenuItem>
          <SidebarMenuButton
            asChild
            tooltip={NAV_DASHBOARD.title}
            isActive={isPathActive(location.pathname, NAV_DASHBOARD.url)}
          >
            <Link
              to={NAV_DASHBOARD.url}
              state={FOCUS_MAIN_HEADING_STATE}
              onClick={handleNavigation}
            >
              <NAV_DASHBOARD.icon />
              <span>{NAV_DASHBOARD.title}</span>
            </Link>
          </SidebarMenuButton>
        </SidebarMenuItem>
        {groups.map((group) => (
          <GroupNavigation
            key={group.title}
            group={group}
            pathname={location.pathname}
            onNavigate={handleNavigation}
          />
        ))}
      </SidebarMenu>
    </SidebarGroup>
  );
}
