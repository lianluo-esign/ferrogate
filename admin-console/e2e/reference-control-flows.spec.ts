// #340 acceptance — the tenancy / IAM / billing REFERENCE-CONTROL Playwright
// matrix. The reference-control migration (fb5fce7+74878a7) replaced raw
// id/CSV inputs with the shared EntityReferencePicker across projects,
// workspaces, tenant-accounts, tenant-roles, native/virtual key allowlists and
// billing. The generic entity-reference-picker.spec.ts only proves the picker
// primitive (one single-select + one multi-select); this spec exercises #340's
// SPECIFIC flows against the migrated forms:
//
//   * project -> workspace cascading (tenant-aware; changing the project
//     resets and refilters the workspace options);
//   * native key allowlists (allowed models / providers as searchable chips
//     whose submitted payload carries the canonical names, not CSV);
//   * role permissions (the tenant-role binding tenant+role pickers, and the
//     roles form permission multi-select) submitting canonical ids/keys;
//   * tenant-account -> plan single reference binding;
//   * cross-tenant combinations blocked client-side (a workspace owned by
//     another tenant's project is never surfaced by a project-scoped picker);
//   * disabled/deleted (retired) targets flagged as unresolved and unable to
//     be newly selected;
//   * edit forms HYDRATE the human label while the submitted payload PRESERVES
//     the canonical id.
//
// Web-first assertions only (no hard sleeps). Submitted payloads are asserted
// by intercepting the create/update request body. DEV-writes / GATE-runs:
// chromium is not installed in the dev-loop environment, so these are authored
// here and executed by the gate across the three viewport projects.
import type { Page, Request } from "@playwright/test";
import { installAuthenticatedAdminApi } from "./support/admin-api";
import {
  attachViewportScreenshot,
  expect,
  expectNoAxeViolations,
  expectNoDocumentOverflow,
  test,
} from "./support/ui-contract";

test.beforeEach(async ({ page }) => {
  await installAuthenticatedAdminApi(page);
});

/**
 * Fulfil every mutating Admin API request (POST/PUT/PATCH) with a benign 200 so
 * the form's success path runs, while deferring reads to the shared contract
 * mock. Paired with {@link page.waitForRequest} the test asserts the exact
 * submitted payload without the request 501-ing on the unmocked-route fallback.
 */
async function stubMutations(page: Page): Promise<void> {
  await page.route(
    (url) => url.pathname.startsWith("/admin/v1/"),
    async (route) => {
      const method = route.request().method();
      if (method === "POST" || method === "PUT" || method === "PATCH") {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({ object: "ok" }),
        });
        return;
      }
      await route.fallback();
    },
  );
}

function isMutation(request: Request, pathname: string, method = "POST"): boolean {
  return request.method() === method && new URL(request.url()).pathname === pathname;
}

test("project selection cascades and tenant-scopes the native key workspace picker", async ({
  page,
}, testInfo) => {
  await page.goto("/app/api-keys-native");
  await expect(page.getByRole("heading", { name: "API keys" })).toBeVisible();
  await page.getByRole("button", { name: "New" }).click();

  const projectPicker = page.getByRole("combobox", { name: "Project" });
  const workspacePicker = page.getByRole("combobox", { name: "Workspace" });

  // The workspace picker is inert until its parent project is chosen: a stale
  // project-A/workspace-B (cross-tenant) pairing is structurally impossible.
  await expect(workspacePicker).toBeDisabled();

  await projectPicker.click();
  await page.getByRole("searchbox", { name: "Search Project" }).fill("Production payments");
  await page.getByRole("option", { name: /Production payments routing/ }).click();
  await expect(workspacePicker).toBeEnabled();

  await workspacePicker.click();
  // Project A's own workspace is offered; the workspace that belongs to another
  // tenant's project is never in the project-scoped list (cross-tenant blocked).
  await expect(page.getByRole("option", { name: /Acme production US-East/ })).toBeVisible();
  await expect(page.getByRole("option", { name: /Globex/ })).toHaveCount(0);
  await page.getByRole("searchbox", { name: "Search Workspace" }).fill("Globex");
  await expect(page.getByText("No matching records.")).toBeVisible();
  await page.getByRole("searchbox", { name: "Search Workspace" }).fill("");
  await page.getByRole("option", { name: /Acme production US-East/ }).click();

  await expect(page.getByRole("list", { name: "Selected Workspace" })).toContainText(
    "Acme production US-East",
  );

  // Re-selecting a different project clears the now-invalid workspace and the
  // reopened picker refilters to the NEW project's workspaces only.
  await projectPicker.click();
  await page.getByRole("searchbox", { name: "Search Project" }).fill("Project 02 cross-region");
  await page.getByRole("option", { name: /Project 02 cross-region/ }).click();
  await expect(page.getByRole("list", { name: "Selected Workspace" })).toHaveCount(0);

  await workspacePicker.click();
  await expect(page.getByRole("option", { name: /Acme cross-region EU-West/ })).toBeVisible();
  await expect(page.getByRole("option", { name: /Acme production US-East/ })).toHaveCount(0);
  await page.getByRole("button", { name: "Close" }).click();

  await expectNoDocumentOverflow(page, testInfo);
  await expectNoAxeViolations(page, testInfo, ["critical", "serious"]);
  await attachViewportScreenshot(page, testInfo, "project-workspace-cascade");
});

test("native key allowlists select model and provider chips and submit canonical names", async ({
  page,
}, testInfo) => {
  await stubMutations(page);
  await page.goto("/app/api-keys-native");
  await page.getByRole("button", { name: "New" }).click();

  // Required fields render their label with a trailing " *".
  await page.getByRole("textbox", { name: "Name *", exact: true }).fill("Analytics ingestion key");

  await page.getByRole("combobox", { name: "Allowed models" }).click();
  await page.getByRole("searchbox", { name: "Search Allowed models" }).fill("gpt-4.1-mini");
  await page.getByRole("option", { name: "gpt-4.1-mini" }).click();
  await page.getByRole("searchbox", { name: "Search Allowed models" }).fill("claude");
  await page.getByRole("option", { name: "claude-sonnet-4" }).click();
  await page.getByRole("button", { name: "Close" }).click();

  const selectedModels = page.getByRole("list", { name: "Selected Allowed models" });
  await expect(selectedModels).toContainText("gpt-4.1-mini");
  await expect(selectedModels).toContainText("claude-sonnet-4");

  await page.getByRole("combobox", { name: "Allowed providers" }).click();
  await page.getByRole("searchbox", { name: "Search Allowed providers" }).fill("openai");
  await page.getByRole("option", { name: "openai" }).click();
  await page.getByRole("button", { name: "Close" }).click();
  await expect(page.getByRole("list", { name: "Selected Allowed providers" })).toContainText(
    "openai",
  );

  const [request] = await Promise.all([
    page.waitForRequest((r) => isMutation(r, "/admin/v1/api-keys")),
    page.getByRole("button", { name: "Create" }).click(),
  ]);
  const body = request.postDataJSON() as Record<string, unknown>;
  expect(body.name).toBe("Analytics ingestion key");
  expect(body.allowed_models).toEqual(["gpt-4.1-mini", "claude-sonnet-4"]);
  expect(body.allowed_providers).toEqual(["openai"]);

  await attachViewportScreenshot(page, testInfo, "key-allowlist-chips");
});

test("tenant-account edit hydrates the plan label and preserves the plan id in the payload", async ({
  page,
}, testInfo) => {
  await stubMutations(page);
  await page.goto("/app/tenants");
  await expect(page.getByRole("heading", { name: "Tenant accounts" })).toBeVisible();

  await page.getByRole("button", { name: "Actions for Tenant 1 operations", exact: true }).click();
  await page.getByRole("menuitem", { name: "Edit" }).click();

  // The edit form opens showing the human plan label (hydrated from the plan
  // catalog) while the canonical id stays visible on the chip.
  const selectedPlan = page.getByRole("list", { name: "Selected Plan" });
  await expect(selectedPlan).toContainText("Enterprise Plan");
  await expect(selectedPlan).toContainText("enterprise");

  const [request] = await Promise.all([
    page.waitForRequest((r) => isMutation(r, "/admin/v1/tenant-accounts/tenant-1", "PUT")),
    page.getByRole("button", { name: "Save changes" }).click(),
  ]);
  const body = request.postDataJSON() as Record<string, unknown>;
  expect(body.plan_id).toBe("enterprise");

  await attachViewportScreenshot(page, testInfo, "tenant-plan-binding");
});

test("tenant-role binding picks a tenant and role and assigns the canonical role id", async ({
  page,
}, testInfo) => {
  await stubMutations(page);
  await page.goto("/app/tenant-roles");
  await expect(page.getByRole("heading", { name: "Tenant role bindings" })).toBeVisible();

  // Both the tenant and role sides are entity pickers now (not pasted ids).
  const tenantPicker = page.getByRole("combobox", { name: "Tenant" });
  const rolePicker = page.getByRole("combobox", { name: "Role" });
  await expect(tenantPicker).toBeVisible();
  await expect(rolePicker).toBeVisible();

  await tenantPicker.click();
  await page.getByRole("searchbox", { name: "Search Tenant" }).fill("Tenant 3 operations");
  await page.getByRole("option", { name: /Tenant 3 operations/ }).click();

  await rolePicker.click();
  await page.getByRole("searchbox", { name: "Search Role" }).fill("Billing");
  await page.getByRole("option", { name: /Billing administrator/ }).click();

  const [request] = await Promise.all([
    page.waitForRequest((r) => isMutation(r, "/admin/v1/tenant-roles/tenant-3")),
    page.getByRole("button", { name: "Assign role" }).click(),
  ]);
  const body = request.postDataJSON() as Record<string, unknown>;
  expect(body.role_id).toBe("role-billing-admin-01HZZZZZZZZZZZZZZZZZZZZZZ");

  await expectNoDocumentOverflow(page, testInfo);
  await attachViewportScreenshot(page, testInfo, "tenant-role-binding");
});

test("role form binds permissions as chips and submits canonical permission keys", async ({
  page,
}, testInfo) => {
  await stubMutations(page);
  await page.goto("/app/roles");
  await expect(page.getByRole("heading", { name: "Roles" })).toBeVisible();
  await page.getByRole("button", { name: "New" }).click();

  await page.getByRole("textbox", { name: "Name *", exact: true }).fill("Billing operators");
  await page.getByRole("textbox", { name: "Slug *", exact: true }).fill("billing-operators");

  await page.getByRole("combobox", { name: "Permissions" }).click();
  await page.getByRole("searchbox", { name: "Search Permissions" }).fill("administration");
  await page.getByRole("option", { name: /Read administration/ }).click();
  await page.getByRole("option", { name: /Write administration/ }).click();
  await page.getByRole("button", { name: "Close" }).click();

  const selected = page.getByRole("list", { name: "Selected Permissions" });
  await expect(selected).toContainText("Read administration");
  await expect(selected).toContainText("Write administration");

  const [request] = await Promise.all([
    page.waitForRequest((r) => isMutation(r, "/admin/v1/roles")),
    page.getByRole("button", { name: "Create" }).click(),
  ]);
  const body = request.postDataJSON() as Record<string, unknown>;
  expect(body.name).toBe("Billing operators");
  // The human labels are shown but the canonical permission KEYS are submitted.
  expect(body.permission_keys).toEqual(["admin.read", "admin.write"]);

  await expectNoDocumentOverflow(page, testInfo);
  await expectNoAxeViolations(page, testInfo, ["critical", "serious"]);
  await attachViewportScreenshot(page, testInfo, "role-permission-chips");
});

test("a retired allowlist target is flagged unresolved and cannot be newly selected", async ({
  page,
}, testInfo) => {
  await page.goto("/app/api-keys-native");
  await page
    .getByRole("button", { name: "Actions for Legacy analytics gateway key", exact: true })
    .click();
  await page.getByRole("menuitem", { name: "Edit" }).click();

  // The retired model id the key still holds is no longer in the catalog, so it
  // hydrates to an "Unresolved reference" chip rather than silently vanishing.
  const selectedModels = page.getByRole("list", { name: "Selected Allowed models" });
  await expect(selectedModels).toContainText("gpt-legacy-vision-retired");
  await expect(selectedModels.getByText("Unresolved reference")).toBeVisible();

  // ...and it is not offered for a NEW selection, while a live model still is.
  await page.getByRole("combobox", { name: "Allowed models" }).click();
  await page.getByRole("searchbox", { name: "Search Allowed models" }).fill("gpt-legacy");
  await expect(page.getByText("No matching records.")).toBeVisible();
  await page.getByRole("searchbox", { name: "Search Allowed models" }).fill("gpt-4.1");
  await expect(page.getByRole("option", { name: "gpt-4.1-mini" })).toBeVisible();
  await page.getByRole("button", { name: "Close" }).click();

  await attachViewportScreenshot(page, testInfo, "retired-target-unresolved");
});
