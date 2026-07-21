import { HttpResponse, http } from "msw";
import { describe, expect, it } from "vitest";
import {
  hydrateEntityReference,
  loadEntityReferencePage,
  toEntityReferenceOption,
} from "@/lib/entity-reference-registry";
import type { EntityReferenceConfig } from "@/lib/resource-config";
import { gatewayUrl, server } from "@/test/msw";

const projectReference: EntityReferenceConfig = {
  target: "projects",
  valueKey: "id",
  primaryLabelKey: "name",
  secondaryLabelKeys: ["slug", "tenant_id"],
  pageSize: 2,
};

describe("entity reference registry", () => {
  it("maps declared labels and sends server search, pagination, and dependency filters", async () => {
    server.use(
      http.get(gatewayUrl("/admin/v1/projects"), ({ request }) => {
        const url = new URL(request.url);
        expect(url.searchParams.get("search")).toBe("prod");
        expect(url.searchParams.get("offset")).toBe("2");
        expect(url.searchParams.get("limit")).toBe("2");
        expect(url.searchParams.get("tenant_id")).toBe("tenant-1");
        return HttpResponse.json({
          object: "list",
          data: [
            {
              id: "project-3",
              tenant_id: "tenant-1",
              name: "Production",
              slug: "prod",
            },
          ],
          total: 4,
          offset: 2,
          limit: 2,
        });
      }),
    );

    await expect(
      loadEntityReferencePage("api-key", projectReference, {
        search: "prod",
        offset: 2,
        filters: { tenant_id: "tenant-1" },
      }),
    ).resolves.toEqual({
      options: [
        {
          value: "project-3",
          primaryLabel: "Production",
          secondaryLabel: "prod · tenant-1",
        },
      ],
      nextOffset: 4,
    });
  });

  it("hydrates labels and preserves missing or cross-parent values as unresolved", async () => {
    server.use(
      http.get(gatewayUrl("/admin/v1/projects/:projectId"), ({ params }) => {
        if (params.projectId === "missing") {
          return HttpResponse.json(
            { error: { code: "project_not_found", message: "not found" } },
            { status: 404 },
          );
        }
        return HttpResponse.json({
          object: "project",
          project: {
            id: params.projectId,
            tenant_id: "tenant-1",
            name: "Production",
            slug: "prod",
          },
        });
      }),
    );

    await expect(
      hydrateEntityReference(
        "api-key",
        projectReference,
        "project-1",
        { tenant_id: "tenant-1" },
      ),
    ).resolves.toMatchObject({ value: "project-1", primaryLabel: "Production" });
    await expect(
      hydrateEntityReference(
        "api-key",
        projectReference,
        "project-1",
        { tenant_id: "tenant-2" },
      ),
    ).resolves.toEqual({
      value: "project-1",
      primaryLabel: "project-1",
      unresolved: true,
    });
    await expect(
      hydrateEntityReference("api-key", projectReference, "missing"),
    ).resolves.toEqual({ value: "missing", primaryLabel: "missing", unresolved: true });
  });

  it("rejects records that cannot provide both a value and a human label", () => {
    expect(toEntityReferenceOption({ id: "project-1" }, projectReference)).toBeUndefined();
    expect(toEntityReferenceOption({ name: "Production" }, projectReference)).toBeUndefined();
  });
});
