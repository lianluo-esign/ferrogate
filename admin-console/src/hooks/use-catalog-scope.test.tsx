import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { CatalogScopeToggle } from "@/components/resource/catalog-scope-toggle";
import { useCatalogApiKey } from "@/hooks/use-catalog-api-key";
import { useCatalogScope } from "@/hooks/use-catalog-scope";
import {
  renderWithProviders,
  seedSession,
  TEST_GATEWAY_API_KEY,
} from "@/test/test-utils";

const OPERATOR_KEY = "fg-platform-operator-key";

/** Surfaces the scope state, the resolved credential, and the toggle together. */
function Probe() {
  const { scope, canUsePlatform } = useCatalogScope();
  const apiKey = useCatalogApiKey();
  return (
    <div>
      <span data-testid="scope">{scope}</span>
      <span data-testid="can-platform">{String(canUsePlatform)}</span>
      <span data-testid="api-key">{apiKey}</span>
      <CatalogScopeToggle />
    </div>
  );
}

describe("catalog scope", () => {
  it("lets a superadmin toggle to platform, swapping the resolved credential", async () => {
    seedSession({
      user: {
        id: "user-1",
        email: "root@example.com",
        display_name: "Root",
        superadmin: true,
      },
      platformOperatorApiKey: OPERATOR_KEY,
    });

    renderWithProviders(<Probe />);

    // Superadmin session carries the operator key -> platform scope is available.
    expect(screen.getByTestId("can-platform")).toHaveTextContent("true");
    // Default scope is tenant, so the tenant gateway key is used.
    expect(screen.getByTestId("scope")).toHaveTextContent("tenant");
    expect(screen.getByTestId("api-key")).toHaveTextContent(TEST_GATEWAY_API_KEY);

    const toggle = screen.getByRole("switch");
    await userEvent.click(toggle);

    // Flipping to platform scope swaps the credential to the operator key.
    expect(screen.getByTestId("scope")).toHaveTextContent("platform");
    expect(screen.getByTestId("api-key")).toHaveTextContent(OPERATOR_KEY);
  });

  it("hides the toggle and pins tenant scope for a non-superadmin", () => {
    seedSession(); // default: no platform-operator credential

    renderWithProviders(<Probe />);

    expect(screen.getByTestId("can-platform")).toHaveTextContent("false");
    expect(screen.getByTestId("scope")).toHaveTextContent("tenant");
    expect(screen.getByTestId("api-key")).toHaveTextContent(TEST_GATEWAY_API_KEY);
    // The toggle renders NULL when platform access is unavailable.
    expect(screen.queryByRole("switch")).toBeNull();
  });
});
