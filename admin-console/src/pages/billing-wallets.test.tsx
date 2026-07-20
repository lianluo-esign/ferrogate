// Component tests for the wallet ops surface (#319).
//
// Load-bearing assertions: the overview + ledger render; adjust POSTs the exact
// `{ delta_credits }` body only after confirmation and only when the amount
// validates; and a mocked 403 on adjust surfaces the operator-required error
// (adjust/charge are platform-operator-only, #229/#232).
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse, http } from "msw";
import { beforeEach, describe, expect, it } from "vitest";
import BillingWalletsPage from "@/pages/billing-wallets";
import type { AdminSchema } from "@/lib/gateway-client";
import { gatewayUrl, mockAdminError, server } from "@/test/msw";
import { renderWithProviders, seedSession } from "@/test/test-utils";

type AdminWallet = AdminSchema<"AdminWallet">;

const WALLETS_PATH = "/admin/v1/wallets";

function wallet(overrides: Partial<AdminWallet> = {}): AdminWallet {
  return {
    tenant_id: "org-acme",
    balance_credits: 250_000,
    auto_recharge_threshold_credits: 50_000,
    auto_recharge_amount_credits: 100_000,
    dunning: false,
    created_at_unix: 1_700_000_000,
    updated_at_unix: 1_700_000_500,
    ...overrides,
  };
}

function mockWallets(rows: AdminWallet[]): void {
  server.use(
    http.get(gatewayUrl(WALLETS_PATH), () =>
      HttpResponse.json({ object: "list", data: rows }),
    ),
  );
}

function mockLedger(tenantId: string, entries: unknown[]): void {
  server.use(
    http.get(gatewayUrl(`${WALLETS_PATH}/${tenantId}/ledger`), () =>
      HttpResponse.json({ object: "list", data: entries }),
    ),
  );
}

function ledgerEntry() {
  return {
    id: "led-1",
    request_id: "req-led-1",
    logical_model: "gpt-4o",
    provider: "openai",
    provider_model: "gpt-4o-2024",
    credits: 1234,
    status_code: 200,
    wallet_delta_credits: -1234,
    wallet_balance_after_credits: 248_766,
    occurred_at_unix: 1_700_000_400,
  };
}

beforeEach(() => {
  seedSession();
});

describe("BillingWalletsPage overview", () => {
  it("renders wallet balance, auto-recharge, and dunning state", async () => {
    mockWallets([wallet({ dunning: true })]);

    renderWithProviders(<BillingWalletsPage />);

    expect(await screen.findByText("org-acme")).toBeInTheDocument();
    expect(screen.getByText("250,000")).toBeInTheDocument();
    expect(screen.getByText("≤ 50,000 → +100,000")).toBeInTheDocument();
    expect(screen.getByText("dunning")).toBeInTheDocument();
  });

  it("shows an empty state when no wallets exist", async () => {
    mockWallets([]);

    renderWithProviders(<BillingWalletsPage />);

    expect(await screen.findByText("No wallets provisioned.")).toBeInTheDocument();
  });

  it("surfaces a list-load failure", async () => {
    mockAdminError("get", WALLETS_PATH, 403, "forbidden", "missing admin scope");

    renderWithProviders(<BillingWalletsPage />);

    expect(
      await screen.findByText(/Failed to load wallets: missing admin scope/),
    ).toBeInTheDocument();
  });

  it("loads and renders the ledger when a wallet is selected", async () => {
    const user = userEvent.setup();
    mockWallets([wallet()]);
    mockLedger("org-acme", [ledgerEntry()]);

    renderWithProviders(<BillingWalletsPage />);
    await screen.findByText("org-acme");

    await user.click(screen.getByRole("button", { name: "Ledger" }));

    expect(await screen.findByText("gpt-4o")).toBeInTheDocument();
    expect(screen.getByText("openai/gpt-4o-2024")).toBeInTheDocument();
    expect(screen.getByText("req-led-1")).toBeInTheDocument();
    expect(screen.getByText("248,766")).toBeInTheDocument();
  });
});

describe("BillingWalletsPage adjust action", () => {
  it("blocks submission until a non-zero integer delta is entered", async () => {
    const user = userEvent.setup();
    mockWallets([wallet()]);

    renderWithProviders(<BillingWalletsPage />);
    await screen.findByText("org-acme");

    await user.click(screen.getByRole("button", { name: "Adjust" }));
    const dialog = await screen.findByRole("dialog");
    const apply = within(dialog).getByRole("button", { name: "Apply adjustment" });

    // Empty -> disabled.
    expect(apply).toBeDisabled();

    // Non-numeric -> still disabled.
    await user.type(within(dialog).getByLabelText("Delta (credits)"), "abc");
    expect(apply).toBeDisabled();

    // Zero -> still disabled.
    await user.clear(within(dialog).getByLabelText("Delta (credits)"));
    await user.type(within(dialog).getByLabelText("Delta (credits)"), "0");
    expect(apply).toBeDisabled();

    // Valid -> enabled.
    await user.clear(within(dialog).getByLabelText("Delta (credits)"));
    await user.type(within(dialog).getByLabelText("Delta (credits)"), "100000");
    expect(apply).toBeEnabled();
  });

  it("posts the exact delta_credits body after confirmation", async () => {
    const user = userEvent.setup();
    mockWallets([wallet()]);
    let adjustBody: unknown = null;
    server.use(
      http.post(gatewayUrl(`${WALLETS_PATH}/org-acme/adjust`), async ({ request }) => {
        adjustBody = await request.json();
        return HttpResponse.json({ object: "wallet", wallet: wallet() });
      }),
    );

    renderWithProviders(<BillingWalletsPage />);
    await screen.findByText("org-acme");

    await user.click(screen.getByRole("button", { name: "Adjust" }));
    const dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText("Delta (credits)"), "-50000");
    await user.click(within(dialog).getByRole("button", { name: "Apply adjustment" }));

    await waitFor(() => expect(adjustBody).toEqual({ delta_credits: -50000 }));
  });

  it("surfaces an operator-required 403 on adjust", async () => {
    const user = userEvent.setup();
    mockWallets([wallet()]);
    mockAdminError(
      "post",
      `${WALLETS_PATH}/org-acme/adjust`,
      403,
      "forbidden",
      "platform operator scope required",
    );

    renderWithProviders(<BillingWalletsPage />);
    await screen.findByText("org-acme");

    await user.click(screen.getByRole("button", { name: "Adjust" }));
    const dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText("Delta (credits)"), "100000");
    await user.click(within(dialog).getByRole("button", { name: "Apply adjustment" }));

    expect(
      await within(dialog).findByText("platform operator scope required"),
    ).toBeInTheDocument();
  });
});

describe("BillingWalletsPage charge action", () => {
  it("posts amount_usd_cents + payment method after validation", async () => {
    const user = userEvent.setup();
    mockWallets([wallet()]);
    let chargeBody: unknown = null;
    server.use(
      http.post(gatewayUrl(`${WALLETS_PATH}/org-acme/charge`), async ({ request }) => {
        chargeBody = await request.json();
        return HttpResponse.json({
          object: "wallet_charge",
          succeeded: true,
          provider_charge_id: "ch_123",
          decline_reason: null,
          wallet: wallet(),
        });
      }),
    );

    renderWithProviders(<BillingWalletsPage />);
    await screen.findByText("org-acme");

    await user.click(screen.getByRole("button", { name: "Charge" }));
    const dialog = await screen.findByRole("dialog");
    const capture = within(dialog).getByRole("button", { name: "Capture charge" });

    // Zero cents -> below the 1-cent minimum, blocked.
    await user.type(within(dialog).getByLabelText("Amount (USD cents)"), "0");
    expect(capture).toBeDisabled();

    await user.clear(within(dialog).getByLabelText("Amount (USD cents)"));
    await user.type(within(dialog).getByLabelText("Amount (USD cents)"), "5000");
    await user.type(
      within(dialog).getByLabelText("Payment method id (optional)"),
      "pm_default",
    );
    await user.click(capture);

    await waitFor(() =>
      expect(chargeBody).toEqual({
        amount_usd_cents: 5000,
        payment_method_id: "pm_default",
      }),
    );
  });

  it("surfaces a declined charge without closing the dialog", async () => {
    const user = userEvent.setup();
    mockWallets([wallet()]);
    server.use(
      http.post(gatewayUrl(`${WALLETS_PATH}/org-acme/charge`), () =>
        HttpResponse.json({
          object: "wallet_charge",
          succeeded: false,
          provider_charge_id: "ch_declined",
          decline_reason: "card_declined",
          wallet: wallet(),
        }),
      ),
    );

    renderWithProviders(<BillingWalletsPage />);
    await screen.findByText("org-acme");

    await user.click(screen.getByRole("button", { name: "Charge" }));
    const dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText("Amount (USD cents)"), "5000");
    await user.click(within(dialog).getByRole("button", { name: "Capture charge" }));

    expect(await within(dialog).findByText("card_declined")).toBeInTheDocument();
  });
});
