import type { AdminSchema } from "@/lib/gateway-client";
import BillingPaymentMethodsPage from "@/pages/billing-payment-methods";
import { gatewayUrl, server } from "@/test/msw";
import { renderWithProviders, seedSession } from "@/test/test-utils";
// Component tests for the payment-methods ops surface (#319): list requires a
// tenant filter (the gateway needs a tenant_id query), create posts the full
// body, and delete flows through a confirmation.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { beforeEach, expect, it } from "vitest";

type AdminPaymentMethod = AdminSchema<"AdminPaymentMethod">;

const PM_PATH = "/admin/v1/payment-methods";

function method(overrides: Partial<AdminPaymentMethod> = {}): AdminPaymentMethod {
  return {
    id: "pm-1",
    tenant_id: "org-acme",
    provider: "stripe",
    provider_customer_id: "cus_123",
    provider_payment_method_id: "pm_456",
    is_default: true,
    created_at_unix: 1_700_000_000,
    ...overrides,
  };
}

// #340: the tenant filter is a shared #337 entity picker now. Mock the
// tenant-accounts list (picker options) + detail (hydration of the selected
// value); onUnhandledRequest is "error", so an un-mocked picker call fails.
function mockTenantAccounts() {
  server.use(
    http.get(gatewayUrl("/admin/v1/tenant-accounts"), () =>
      HttpResponse.json({ object: "list", data: [{ id: "org-acme", name: "Acme", slug: "acme" }] }),
    ),
    http.get(gatewayUrl("/admin/v1/tenant-accounts/org-acme"), () =>
      HttpResponse.json({
        object: "tenant",
        tenant: { id: "org-acme", name: "Acme", slug: "acme" },
      }),
    ),
  );
}

/** Select the "Acme" tenant (id org-acme) through the tenant picker. */
async function selectTenant(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole("combobox", { name: "Tenant" }));
  await user.click(await screen.findByRole("option", { name: /Acme/ }));
}

beforeEach(() => {
  seedSession();
  mockTenantAccounts();
});

it("prompts for a tenant id before listing", async () => {
  renderWithProviders(<BillingPaymentMethodsPage />);

  expect(
    await screen.findByText("Enter a tenant id above to load payment methods."),
  ).toBeInTheDocument();
  // The tenant filter is a picker, not a raw id textbox.
  expect(screen.getByRole("combobox", { name: "Tenant" })).toBeInTheDocument();
  expect(screen.queryByRole("textbox", { name: /Tenant/ })).not.toBeInTheDocument();
});

it("lists payment methods for the selected tenant with a tenant_id query", async () => {
  const user = userEvent.setup();
  let seenTenant: string | null = null;
  server.use(
    http.get(gatewayUrl(PM_PATH), ({ request }) => {
      seenTenant = new URL(request.url).searchParams.get("tenant_id");
      return HttpResponse.json({ object: "list", data: [method()] });
    }),
  );

  renderWithProviders(<BillingPaymentMethodsPage />);
  await selectTenant(user);

  expect(await screen.findByText("pm-1")).toBeInTheDocument();
  expect(screen.getByText("cus_123")).toBeInTheDocument();
  expect(screen.getByText("default")).toBeInTheDocument();
  await waitFor(() => expect(seenTenant).toBe("org-acme"));
});

it("registers a new payment method with the full body", async () => {
  const user = userEvent.setup();
  let createBody: unknown = null;
  server.use(
    http.get(gatewayUrl(PM_PATH), () => HttpResponse.json({ object: "list", data: [] })),
    http.post(gatewayUrl(PM_PATH), async ({ request }) => {
      createBody = await request.json();
      return HttpResponse.json({ object: "payment_method", payment_method: method() });
    }),
  );

  renderWithProviders(<BillingPaymentMethodsPage />);
  await selectTenant(user);

  await user.click(await screen.findByRole("button", { name: "Register payment method" }));
  const dialog = await screen.findByRole("dialog");
  await user.type(within(dialog).getByLabelText("Provider"), "stripe");
  await user.type(within(dialog).getByLabelText("Provider customer id"), "cus_123");
  await user.type(within(dialog).getByLabelText("Provider payment method id"), "pm_456");
  await user.click(within(dialog).getByRole("button", { name: "Register" }));

  await waitFor(() =>
    expect(createBody).toEqual({
      tenant_id: "org-acme",
      provider: "stripe",
      provider_customer_id: "cus_123",
      provider_payment_method_id: "pm_456",
      is_default: false,
    }),
  );
});

it("deletes a payment method after confirmation", async () => {
  const user = userEvent.setup();
  let deleted = false;
  server.use(
    http.get(gatewayUrl(PM_PATH), () =>
      HttpResponse.json({ object: "list", data: deleted ? [] : [method()] }),
    ),
    http.delete(gatewayUrl(`${PM_PATH}/pm-1`), () => {
      deleted = true;
      return HttpResponse.json({ object: "payment_method_deleted", id: "pm-1" });
    }),
  );

  renderWithProviders(<BillingPaymentMethodsPage />);
  await selectTenant(user);
  await screen.findByText("pm-1");

  await user.click(screen.getByRole("button", { name: "Delete" }));
  const dialog = await screen.findByRole("alertdialog");
  await user.click(within(dialog).getByRole("button", { name: "Delete" }));

  await waitFor(() => expect(deleted).toBe(true));
  await waitFor(() =>
    expect(screen.getByText("No payment methods for this tenant.")).toBeInTheDocument(),
  );
});
