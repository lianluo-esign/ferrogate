import createClient from "openapi-fetch";

import type { components, paths } from "./generated.js";

const client = createClient<paths>({ baseUrl: "http://127.0.0.1:8080" });

const project: components["schemas"]["AdminProjectCreateRequest"] = {
  tenant_id: "tenant-1",
  name: "Example",
  slug: "example",
};
const quota: components["schemas"]["AdminQuotaPolicyMutation"] = {
  rpm_limit: 60,
  enabled: true,
};
const wallet: components["schemas"]["AdminWalletAdjustRequest"] = {
  delta_credits: 100,
};
const guardrail: components["schemas"]["GuardrailPolicyDryRunRequest"] = {
  stage: "request",
  text: "inspect this request",
};

void client.POST("/admin/v1/projects", { body: project });
void client.PATCH("/admin/v1/quota-policies/{scope_type}/{scope_id}", {
  params: { path: { scope_type: "tenant", scope_id: "tenant-1" } },
  body: quota,
});
void client.POST("/admin/v1/wallets/{tenant_id}/adjust", {
  params: { path: { tenant_id: "tenant-1" } },
  body: wallet,
});
void client.POST("/admin/v1/guardrail-policies/{policy_id}/dry-run", {
  params: { path: { policy_id: "pii" } },
  body: guardrail,
});
void client.GET("/v1/assets/{asset_type}/{name}/{version}", {
  params: {
    path: { asset_type: "skill", name: "redactor", version: "1.0.0" },
  },
  parseAs: "arrayBuffer",
});
