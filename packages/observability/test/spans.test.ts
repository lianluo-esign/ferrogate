import { describe, expect, test } from "vitest";
import {
  BILLING_WRITE_SPAN,
  GATEWAY_REQUEST_SPAN,
  GatewaySpanKind,
  defaultSpanTemplates,
} from "../src/index.js";

describe("gateway span templates", () => {
  test("cover the request → provider → metering hierarchy", () => {
    const templates = defaultSpanTemplates();

    expect(templates[0]?.name).toBe("ferrogate.gateway.request");
    expect(
      templates.some(
        (t) =>
          t.kind === GatewaySpanKind.ProviderDispatch &&
          t.fields.includes("retryable"),
      ),
    ).toBe(true);
    expect(
      templates.some(
        (t) =>
          t.kind === GatewaySpanKind.BillingWrite &&
          t.name === "ferrogate.metering.write" &&
          t.fields.includes("total_tokens") &&
          t.fields.includes("result"),
      ),
    ).toBe(true);
  });

  test("there are exactly 6 canonical templates", () => {
    expect(defaultSpanTemplates().length).toBe(6);
  });

  test("named constants match their kinds", () => {
    expect(GATEWAY_REQUEST_SPAN.kind).toBe(GatewaySpanKind.GatewayRequest);
    expect(BILLING_WRITE_SPAN.name).toBe("ferrogate.metering.write");
  });
});
