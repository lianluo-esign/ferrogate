import OpsConfigPage from "@/pages/ops-config";
import { gatewayUrl, server } from "@/test/msw";
import { renderWithProviders, seedSession } from "@/test/test-utils";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { beforeEach, describe, expect, it } from "vitest";

beforeEach(() => {
  seedSession();
});

describe("OpsConfigPage", () => {
  it("shows validation errors from an invalid config and keeps reload locked", async () => {
    const user = userEvent.setup();
    server.use(
      http.post(gatewayUrl("/admin/v1/config/validate"), () =>
        HttpResponse.json({
          valid: false,
          snapshot: null,
          reload_mode: null,
          listener_reload_required: false,
          reload_reason: null,
          error: "line 3: unknown provider 'nope'",
        }),
      ),
    );

    renderWithProviders(<OpsConfigPage />);

    // Reload starts locked (no clean validation yet).
    expect(screen.getByRole("button", { name: "Reload" })).toBeDisabled();

    await user.click(screen.getByRole("button", { name: "Validate" }));

    expect(await screen.findByText("line 3: unknown provider 'nope'")).toBeInTheDocument();
    // Still locked after a failed validation.
    expect(screen.getByRole("button", { name: "Reload" })).toBeDisabled();
  });

  it("unlocks reload after a clean validate and POSTs reload only after confirmation", async () => {
    const user = userEvent.setup();
    let reloadCalled = false;
    server.use(
      http.post(gatewayUrl("/admin/v1/config/validate"), () =>
        HttpResponse.json({
          valid: true,
          snapshot: "snap-candidate",
          reload_mode: "hot",
          listener_reload_required: false,
          reload_reason: null,
          error: null,
        }),
      ),
      http.post(gatewayUrl("/admin/v1/config/reload"), () => {
        reloadCalled = true;
        return HttpResponse.json({
          valid: true,
          committed: true,
          mode: "hot",
          active_snapshot: "snap-candidate",
          candidate_snapshot: "snap-candidate",
          error: null,
        });
      }),
    );

    renderWithProviders(<OpsConfigPage />);

    await user.click(screen.getByRole("button", { name: "Validate" }));

    // Reload unlocks once validation returns valid.
    await waitFor(() => expect(screen.getByRole("button", { name: "Reload" })).toBeEnabled());
    expect(reloadCalled).toBe(false);

    // Opening the confirm dialog must not POST yet.
    await user.click(screen.getByRole("button", { name: "Reload" }));
    expect(await screen.findByText("Reload gateway config?")).toBeInTheDocument();
    expect(reloadCalled).toBe(false);

    // Confirming POSTs the reload.
    await user.click(screen.getByRole("button", { name: "Reload now" }));

    await waitFor(() => expect(reloadCalled).toBe(true));
    expect(await screen.findByText("committed")).toBeInTheDocument();
  });

  it("re-locks reload when the operator edits after a clean validate", async () => {
    const user = userEvent.setup();
    server.use(
      http.post(gatewayUrl("/admin/v1/config/validate"), () =>
        HttpResponse.json({
          valid: true,
          snapshot: "snap-1",
          reload_mode: "hot",
          listener_reload_required: false,
          reload_reason: null,
          error: null,
        }),
      ),
    );

    renderWithProviders(<OpsConfigPage />);

    // Switch to an inline format so there is an editable textarea.
    await user.click(screen.getByRole("combobox"));
    await user.click(await screen.findByRole("option", { name: "Inline TOML" }));

    const textarea = screen.getByLabelText("Config");
    fireEvent.change(textarea, { target: { value: "port = 8080" } });
    await user.click(screen.getByRole("button", { name: "Validate" }));

    await waitFor(() => expect(screen.getByRole("button", { name: "Reload" })).toBeEnabled());

    // Any further edit invalidates the prior validation and re-locks reload.
    fireEvent.change(textarea, { target: { value: "port = 9090" } });
    await waitFor(() => expect(screen.getByRole("button", { name: "Reload" })).toBeDisabled());
  });
});
