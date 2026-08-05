/** The control plane must borrow the gateway's tenant object namespace. */
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";

function bindingBody(): string {
  const toml = (env as unknown as { TEST_WRANGLER_TOML?: string }).TEST_WRANGLER_TOML;
  if (typeof toml !== "string") throw new Error("TEST_WRANGLER_TOML is not bound");
  const stanza = toml
    .match(/\[\[durable_objects\.bindings\]\][\s\S]*?(?=\n\[\[|\n\[[^\[]|$)/g)
    ?.find((entry) => /name\s*=\s*"TENANT_DATA"/.test(entry));
  if (stanza === undefined) throw new Error("TENANT_DATA durable object binding is missing");
  return stanza;
}

describe("TENANT_DATA deployment wiring", () => {
  it("borrows the gateway TenantDataObject namespace", () => {
    const body = bindingBody();
    expect(body).toContain('class_name = "TenantDataObject"');
    expect(body).toContain('script_name = "ferrogate-gateway"');
  });
});
