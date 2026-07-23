import { booleanColumn, type ResourceConfig } from "@/lib/resource-config";

export interface AdminQuotaPolicy extends Record<string, unknown> {
  id: string;
  scope_type: "tenant" | "project" | "workspace" | "key";
  scope_id: string;
  model_allowlist: string[];
  rpm_limit: number | null;
  tpm_limit: number | null;
  monthly_budget_usd: number | null;
  asset_storage_quota_bytes: number | null;
  enabled: boolean;
  created_at_unix: number;
  updated_at_unix: number;
}

// Per-resource operator copy is migrated onto the typed i18n catalog (#348):
// `titleKey`/`descriptionKey`, column `headerKey`, field `labelKey`/
// `descriptionKey`, and select-option `labelKey` resolve under the active
// locale in the shared resource-CRUD framework. Resource IDs, field `name`s,
// and option `value`s stay data-driven; the boolean Yes/No cell now localizes
// via `booleanColumn` (#385).
export const quotaPoliciesConfig: ResourceConfig<AdminQuotaPolicy> = {
  key: "quota-policies",
  titleKey: "resource.quotaPolicies.title",
  descriptionKey: "resource.quotaPolicies.description",
  basePath: "/admin/v1/quota-policies",
  idField: "id",
  resolveDetailPath: (row) => `${row.scope_type}/${row.scope_id}`,
  columns: [
    { key: "scope_type", headerKey: "resource.quotaPolicies.col.scope" },
    { key: "scope_id", headerKey: "resource.quotaPolicies.col.scopeId" },
    { key: "rpm_limit", headerKey: "resource.quotaPolicies.col.rpmLimit" },
    { key: "tpm_limit", headerKey: "resource.quotaPolicies.col.tpmLimit" },
    { key: "monthly_budget_usd", headerKey: "resource.quotaPolicies.col.monthlyBudget" },
    { key: "asset_storage_quota_bytes", headerKey: "resource.quotaPolicies.col.assetQuota" },
    booleanColumn<AdminQuotaPolicy>({ key: "enabled", headerKey: "resource.quotaPolicies.col.enabled" }),
  ],
  fields: [
    {
      name: "scope_type",
      labelKey: "resource.quotaPolicies.field.scopeType",
      type: "select",
      required: true,
      createOnly: true,
      options: [
        { labelKey: "resource.quotaPolicies.option.scopeType.tenant", value: "tenant" },
        { labelKey: "resource.quotaPolicies.option.scopeType.project", value: "project" },
        { labelKey: "resource.quotaPolicies.option.scopeType.workspace", value: "workspace" },
        { labelKey: "resource.quotaPolicies.option.scopeType.key", value: "key" },
      ],
    },
    // scope_id targets a different entity kind per scope_type (#341). The scoped
    // reference switches the picker's target by the sibling `scope_type` value,
    // so operators pick a real tenant/project/workspace/key row (with enough
    // context to tell duplicates apart) and cannot submit an ID from the wrong
    // scope. Changing scope_type clears any stale selection. It stays
    // `createOnly` — a policy's scope is fixed at creation (the PUT path is
    // `${scope_type}/${scope_id}`).
    {
      name: "scope_id",
      labelKey: "resource.quotaPolicies.field.scopeId",
      type: "entity",
      required: true,
      createOnly: true,
      scopedReference: {
        field: "scope_type",
        byValue: {
          tenant: {
            target: "tenant-accounts",
            valueKey: "id",
            primaryLabelKey: "name",
            secondaryLabelKeys: ["slug"],
          },
          project: {
            target: "projects",
            valueKey: "id",
            primaryLabelKey: "name",
            secondaryLabelKeys: ["slug", "tenant_id"],
          },
          workspace: {
            target: "workspaces",
            valueKey: "id",
            primaryLabelKey: "name",
            secondaryLabelKeys: ["slug", "project_id"],
          },
          key: {
            target: "virtual-keys",
            valueKey: "id",
            primaryLabelKey: "name",
            secondaryLabelKeys: ["key_prefix", "workspace_id"],
          },
        },
      },
    },
    {
      name: "model_allowlist",
      labelKey: "resource.quotaPolicies.field.modelAllowlist",
      type: "entities",
      descriptionKey: "resource.quotaPolicies.field.modelAllowlist.desc",
      reference: {
        target: "models",
        valueKey: "name",
        primaryLabelKey: "name",
        secondaryLabelKeys: ["provider", "provider_model"],
      },
    },
    { name: "rpm_limit", labelKey: "resource.quotaPolicies.field.rpmLimit", type: "number" },
    { name: "tpm_limit", labelKey: "resource.quotaPolicies.field.tpmLimit", type: "number" },
    {
      name: "monthly_budget_usd",
      labelKey: "resource.quotaPolicies.field.monthlyBudget",
      type: "number",
    },
    {
      name: "asset_storage_quota_bytes",
      labelKey: "resource.quotaPolicies.field.assetQuota",
      type: "number",
      descriptionKey: "resource.quotaPolicies.field.assetQuota.desc",
    },
    { name: "enabled", labelKey: "resource.quotaPolicies.field.enabled", type: "boolean" },
  ],
};
