import { HttpResponse, http } from "msw";
import { describe, expect, it } from "vitest";
import {
  adminDelete,
  adminGet,
  adminPost,
  adminPut,
} from "@/lib/gateway-client";
import { ApiError } from "@/types/auth";
import { gatewayUrl, mockAdminError, server } from "@/test/msw";

const API_KEY = "fg-test-key";

describe("typed OpenAPI client (adminGet/adminPost/...)", () => {
  it("adminGet returns the contract-typed list body", async () => {
    server.use(
      http.get(gatewayUrl("/admin/v1/plans"), () =>
        HttpResponse.json({
          object: "list",
          data: [
            {
              id: "p1",
              name: "Free",
              slug: "free",
              mcp_enabled: false,
              self_hosted_workers_enabled: false,
              default_model_allowlist: [],
              asset_hosting_enabled: false,
              extension_tools_enabled: false,
              created_at_unix: 1,
              updated_at_unix: 1,
            },
          ],
        }),
      ),
    );

    const page = await adminGet(API_KEY, "/admin/v1/plans");
    // `page` is typed from the generated contract: `.data[].slug` compiles,
    // a typo like `.data[0].slugg` would be a build error.
    expect(page.object).toBe("list");
    expect(page.data[0].slug).toBe("free");
  });

  it("adminPut substitutes {path} params from the contract template", async () => {
    let hitPath: string | null = null;
    let body: unknown = null;
    server.use(
      http.put(gatewayUrl("/admin/v1/plans/:planId"), async ({ request }) => {
        hitPath = new URL(request.url).pathname;
        body = await request.json();
        return HttpResponse.json({
          object: "plan",
          plan: {
            id: "plan-1",
            name: "Pro",
            slug: "pro",
            mcp_enabled: true,
            self_hosted_workers_enabled: false,
            default_model_allowlist: [],
            asset_hosting_enabled: false,
            extension_tools_enabled: false,
            created_at_unix: 1,
            updated_at_unix: 2,
          },
        });
      }),
    );

    const response = await adminPut(
      API_KEY,
      "/admin/v1/plans/{plan_id}",
      { name: "Pro" },
      { params: { plan_id: "plan-1" } },
    );

    expect(hitPath).toBe("/admin/v1/plans/plan-1");
    expect(body).toEqual({ name: "Pro" });
    expect(response.plan.name).toBe("Pro");
  });

  it("adminPost sends the typed request body and returns the mutation response", async () => {
    let body: unknown = null;
    server.use(
      http.post(gatewayUrl("/admin/v1/tenant-accounts"), async ({ request }) => {
        body = await request.json();
        return HttpResponse.json({
          object: "tenant_account",
          tenant: {
            id: "t1",
            name: "Acme",
            slug: "acme",
            status: "active",
            plan_id: "free",
            created_at_unix: 1,
            updated_at_unix: 1,
          },
        });
      }),
    );

    const response = await adminPost(API_KEY, "/admin/v1/tenant-accounts", {
      name: "Acme",
      slug: "acme",
    });

    expect(body).toEqual({ name: "Acme", slug: "acme" });
    expect(response.tenant.id).toBe("t1");
  });

  it("adminDelete substitutes {key_id} and returns the delete acknowledgement", async () => {
    let hitPath: string | null = null;
    server.use(
      http.delete(gatewayUrl("/admin/v1/virtual-keys/:keyId"), ({ request }) => {
        hitPath = new URL(request.url).pathname;
        return HttpResponse.json({ object: "virtual_api_key.deleted", id: "vk-1" });
      }),
    );

    await expect(
      adminDelete(API_KEY, "/admin/v1/virtual-keys/{key_id}", {
        params: { key_id: "vk-1" },
      }),
    ).resolves.toEqual({ object: "virtual_api_key.deleted", id: "vk-1" });
    expect(hitPath).toBe("/admin/v1/virtual-keys/vk-1");
  });

  it("throws the typed ApiError with code/status from the error envelope", async () => {
    mockAdminError("get", "/admin/v1/plans", 429, "rate_limited", "slow down");

    const error = await adminGet(API_KEY, "/admin/v1/plans").catch((e) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 429, code: "rate_limited", message: "slow down" });
  });
});
