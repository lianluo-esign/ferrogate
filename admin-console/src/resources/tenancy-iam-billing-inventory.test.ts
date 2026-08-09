import { entityReferenceRegistry } from "@/lib/entity-reference-registry";
import type { FieldConfig, ResourceConfig } from "@/lib/resource-config";
import { apiKeysConfig } from "@/resources/api-keys";
import { permissionsConfig } from "@/resources/permissions";
import { plansConfig } from "@/resources/plans";
import { projectsConfig } from "@/resources/projects";
import { rolesConfig } from "@/resources/roles";
import { tenantAccountsConfig } from "@/resources/tenant-accounts";
import { virtualKeysConfig } from "@/resources/virtual-keys";
import { workspacesConfig } from "@/resources/workspaces";
import { describe, expect, it } from "vitest";

/**
 * #340 acceptance box 1 + box 7, as an executable inventory.
 *
 * Box 1: "No tenancy/IAM/billing create form asks for a tenant, project,
 * workspace, plan, role, permission, model, provider, or payment-method ID as
 * ordinary free text."
 * Box 7: "the completed field inventory for this domain and no silent
 * exclusions."
 *
 * The inventory shipped with #340 lived only in commit messages (74878a7,
 * amended by 3064f3c), so nothing in the tree failed when a new free-text
 * relationship field was added or when an existing one was justified on a
 * premise that later became false. This test is that missing gate: it walks the
 * declarative field configs of every generic resource in the
 * organization / access-and-policy / billing nav groups and refuses any field
 * that names one of the nine entity kinds box 1 enumerates while still being an
 * ordinary text/CSV input.
 */

// Declarative configs for the three nav groups #340 owns (see
// src/components/layout/nav-config.ts: nav.group.organization,
// nav.group.accessPolicy, nav.group.billing). Bespoke pages in the same groups
// (tenant-roles, tenant-resolved-defaults, billing-payment-methods,
// billing-wallets) drive the shared picker directly and are covered by their
// own page tests; quota-policies and access-policies belong to #341.
const DOMAIN_CONFIGS: ResourceConfig<Record<string, unknown>>[] = [
  tenantAccountsConfig,
  projectsConfig,
  workspacesConfig,
  plansConfig,
  apiKeysConfig,
  virtualKeysConfig,
  rolesConfig,
  permissionsConfig,
] as unknown as ResourceConfig<Record<string, unknown>>[];

/**
 * The nine entity kinds box 1 enumerates, as field-name fragments.
 * `organization` is included because the gateway compares an API key's
 * `organization_id` directly against a `tenant-accounts` row id
 * (crates/ferrogate-cli/src/gateway/api_key_tenancy.rs: `project.tenant_id !=
 * organization_id`), so it is a tenant reference under another name. `user` is
 * deliberately absent: box 1 does not list it and the console exposes no users
 * catalog.
 */
const REFERENCED_ENTITY_KINDS = [
  "tenant",
  "organization",
  "project",
  "workspace",
  "plan",
  "role",
  "permission",
  "model",
  "provider",
  "payment_method",
];

/**
 * Fields that name an entity kind but are not a *reference* to another row:
 * the row's own natural key, and the opaque secret material box 1's non-goals
 * explicitly exclude ("Replacing opaque secret values with selectors").
 */
function isSelfIdentifierOrSecret(
  config: ResourceConfig<Record<string, unknown>>,
  field: FieldConfig,
) {
  if (field.name === config.idField) return true;
  // permissions.key is the natural key of the permission being created.
  if (config.key === "permissions" && field.name === "key") return true;
  // api-keys.key / key_env are the credential itself. (`apiKeysConfig.key` is
  // "api-keys-native" — the native gateway keys of #321, distinct from the
  // durable virtual keys.)
  return config.key === "api-keys-native" && (field.name === "key" || field.name === "key_env");
}

function namesAnEntityKind(name: string) {
  return REFERENCED_ENTITY_KINDS.some((kind) => name.includes(kind));
}

function freeTextEntityReferences() {
  const offenders: string[] = [];
  for (const config of DOMAIN_CONFIGS) {
    for (const field of config.fields) {
      if (isSelfIdentifierOrSecret(config, field)) continue;
      if (!namesAnEntityKind(field.name)) continue;
      if (field.type === "entity" || field.type === "entities") continue;
      if (field.type === "reference-list" || field.type === "workflow-nodes") continue;
      // A bounded `select` is an enumerated choice, not a free-text ID.
      if (field.type === "select") continue;
      offenders.push(`${config.key}.${field.name} (type: ${field.type})`);
    }
  }
  return offenders.sort();
}

describe("#340 tenancy/IAM/billing relationship-field inventory", () => {
  it("asks for no tenant/project/workspace/plan/role/permission/model/provider/payment-method ID as free text", () => {
    expect(
      freeTextEntityReferences(),
      "Acceptance box 1 forbids an ordinary text/CSV input for these entity kinds. " +
        "Migrate the field to the shared #337 picker (type: 'entity'/'entities'), or, if it " +
        "genuinely has no entity source, record that here with the reason (box 7: no silent exclusions).",
    ).toEqual([]);
  });

  /**
   * Box 7, "no silent exclusions", as an executable premise check.
   *
   * The failure this issue was bounced for was NOT a missing field -- it was a
   * justification whose premise had silently become false: `organization_id`
   * was held back as free text because "the console exposes no organizations
   * list endpoint", while `/admin/v1/tenant-accounts` was already registered
   * and already used by projects.ts. Recording an exclusion in prose cannot
   * catch that; asserting its premise can.
   *
   * Corrected inventory for the fields that remain non-pickers in this domain:
   *
   *   api-keys-native.user_id  free text  -- no users catalog exists (asserted
   *                                          below). Box 1 does not list "user".
   *   api-keys-native.scopes   csv        -- auth-time capability strings from
   *   virtual-keys.scopes      csv           ferrogate-cli/src/auth.rs (incl.
   *                                          `*` and provider-facing entries
   *                                          that are not RBAC rows), a
   *                                          different vocabulary from the #182
   *                                          permissions catalog. Not an entity
   *                                          reference at all.
   *
   * Superseded claims from the original inventory (commit 74878a7, amended by
   * 3064f3c), corrected here:
   *
   *   - "api-keys.organization_id: justified-free-text (not guaranteed to be a
   *     tenant row; no list endpoint)" -- FALSE on both halves; the field is now
   *     a tenant-accounts picker. See the comment at api-keys.ts.
   *   - "policies.*: already done upstream (#337/#341), untouched" -- INACCURATE:
   *     `policies.organization_ids` is still `type: "csv"` (policies.ts), and
   *     `policies.api_key_ids` likewise. Those fields are #341's scope, not
   *     this issue's, but they are NOT done and are recorded here as
   *     outstanding rather than left described as complete.
   */
  it("keeps its documented free-text exclusion honest: there is still no users catalog", () => {
    const userIdField = apiKeysConfig.fields.find((field) => field.name === "user_id");
    expect(userIdField?.type).toBe("text");
    // The premise. If a users adapter is ever registered, this fails and forces
    // user_id to be reconsidered instead of coasting on a stale justification.
    expect(Object.keys(entityReferenceRegistry)).not.toContain("users");
  });

  it("catches a newly added free-text relationship field", () => {
    // Falsifiability: the check above only means something if it reacts to a
    // regression. A synthetic tenant-id text field must be reported.
    const synthetic = {
      key: "synthetic",
      idField: "id",
      fields: [{ name: "tenant_id", label: "Tenant", type: "text" }],
    } as unknown as ResourceConfig<Record<string, unknown>>;
    DOMAIN_CONFIGS.push(synthetic);
    try {
      expect(freeTextEntityReferences()).toContain("synthetic.tenant_id (type: text)");
    } finally {
      DOMAIN_CONFIGS.pop();
    }
  });
});
