import { ResourcePage } from "@/components/resource/resource-page";
import { RESOURCE_ROUTES } from "@/resources";
import { useLocation } from "react-router-dom";

export default function ResourceRoutePage() {
  const location = useLocation();
  const route = RESOURCE_ROUTES.find((candidate) => candidate.path === location.pathname);

  if (!route) {
    throw new Error(`No resource configuration registered for ${location.pathname}`);
  }

  return <ResourcePage config={route.config} />;
}
