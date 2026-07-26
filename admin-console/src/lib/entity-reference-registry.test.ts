import { HttpResponse, http } from "msw";
import { describe, expect, it } from "vitest";
import {
  hydrateEntityReference,
  isDisabledEntityRecord,
  loadEntityReferencePage,
  toEntityReferenceOption,
} from "@/lib/entity-reference-registry";
import {
  DISABLED_WHEN_NOT_ENABLED,
  DISABLED_WHEN_STATUS_NOT_ACTIVE,
  type EntityReferenceConfig,
} from "@/lib/resource-config";
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

  // #340 acceptance box 5: the reference layer had no way to model a target that
  // exists but is disabled, so a `status: "suspended"` project or an
  // `enabled: false` model listed indistinguishably from a live one.
  describe("disabled targets", () => {
    const suspendableProject: EntityReferenceConfig = {
      ...projectReference,
      disabledWhen: DISABLED_WHEN_STATUS_NOT_ACTIVE,
    };
    const modelReference: EntityReferenceConfig = {
      target: "models",
      valueKey: "name",
      primaryLabelKey: "name",
      disabledWhen: DISABLED_WHEN_NOT_ENABLED,
    };

    it("flags a row whose status/enabled signal is outside the active set", () => {
      expect(
        toEntityReferenceOption(
          { id: "project-1", name: "Production", slug: "prod", status: "suspended" },
          suspendableProject,
        ),
      ).toMatchObject({ value: "project-1", disabled: true });
      expect(
        toEntityReferenceOption({ name: "gpt-retired", enabled: false }, modelReference),
      ).toMatchObject({ value: "gpt-retired", disabled: true });
    });

    it("leaves active rows selectable, case-insensitively", () => {
      expect(
        toEntityReferenceOption(
          { id: "project-1", name: "Production", slug: "prod", status: "ACTIVE" },
          suspendableProject,
        )?.disabled,
      ).toBeUndefined();
      expect(
        toEntityReferenceOption({ name: "gpt-live", enabled: true }, modelReference)?.disabled,
      ).toBeUndefined();
    });

    // A detail endpoint that projects fewer fields than its list endpoint must
    // not silently lock an operator out of a legitimate target.
    it("treats an absent signal as no signal rather than as disabled", () => {
      expect(
        toEntityReferenceOption(
          { id: "project-1", name: "Production", slug: "prod" },
          suspendableProject,
        )?.disabled,
      ).toBeUndefined();
      expect(isDisabledEntityRecord({ name: "gpt-live" }, modelReference)).toBe(false);
    });

    it("carries the flag through a listed page", async () => {
      server.use(
        http.get(gatewayUrl("/admin/v1/models"), () =>
          HttpResponse.json({
            object: "list",
            data: [
              { name: "gpt-live", enabled: true },
              { name: "gpt-retired", enabled: false },
            ],
            total: 2,
            offset: 0,
            limit: 20,
          }),
        ),
      );

      const page = await loadEntityReferencePage("api-key", modelReference, {
        search: "",
        offset: 0,
        filters: {},
      });

      expect(page.options.map((option) => [option.value, option.disabled])).toEqual([
        ["gpt-live", undefined],
        ["gpt-retired", true],
      ]);
    });
  });
});
