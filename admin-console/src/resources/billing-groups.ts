import type { TranslationKey } from "@/i18n";
import type { AdminSchema } from "@/lib/gateway-client";

/**
 * Platform billing-group resource definition (#946, epic #941).
 *
 * A billing group binds a set of platform provider channels and carries ONE
 * price `multiplier`; a served request's consumed price is the provider's
 * official offering price times the multiplier of the group the request's API
 * key is bound to (`api_keys.billing_group_id`). Group ↔ provider is
 * many-to-many, edited through the dedicated
 * `PUT/DELETE /admin/v1/billing-groups/{id}/providers/{providerId}` endpoints
 * (S2/S3, #943/#944).
 *
 * Unlike `providers.ts` this is NOT a generic `ResourceConfig` registered in
 * `RESOURCE_ROUTES`: the create/patch contract (`BillingGroupMutation`) is
 * `additionalProperties:false` and carries NO `provider_ids`, and the bindings
 * are a SEPARATE sub-resource with its own PUT/DELETE verbs — neither of which
 * the generic CRUD form can drive. So the surface is a bespoke page
 * (`src/pages/billing-groups.tsx`) that consumes this module as its single
 * source of truth for the base path, the typed row shape, and the localized
 * column/field copy. It is `platformScopable`: the surface is platform-operator
 * only (a tenant-scoped caller is fenced with a leak-proof 404), so the page
 * addresses it under the shared #912 catalog-scope machinery.
 */
export type AdminBillingGroup = AdminSchema<"BillingGroup">;
export type BillingGroupMutation = AdminSchema<"BillingGroupMutation">;

export const BILLING_GROUPS_BASE_PATH = "/admin/v1/billing-groups";

export interface BillingGroupColumn {
  key: keyof AdminBillingGroup & string;
  headerKey: TranslationKey;
}

export interface BillingGroupField {
  name: "name" | "multiplier" | "description" | "enabled";
  labelKey: TranslationKey;
  type: "text" | "number" | "textarea" | "boolean";
  required?: boolean;
  /** Minimum accepted numeric value (multiplier is >= 0). */
  min?: number;
}

export const billingGroupsResource = {
  key: "billing-groups",
  titleKey: "resource.billingGroups.title",
  descriptionKey: "resource.billingGroups.description",
  basePath: BILLING_GROUPS_BASE_PATH,
  idField: "id",
  platformScopable: true,
  columns: [
    { key: "name", headerKey: "resource.billingGroups.col.name" },
    { key: "multiplier", headerKey: "resource.billingGroups.col.multiplier" },
    { key: "description", headerKey: "resource.billingGroups.col.description" },
    { key: "enabled", headerKey: "resource.billingGroups.col.enabled" },
  ] satisfies BillingGroupColumn[],
  fields: [
    {
      name: "name",
      labelKey: "resource.billingGroups.field.name",
      type: "text",
      required: true,
    },
    {
      name: "multiplier",
      labelKey: "resource.billingGroups.field.multiplier",
      type: "number",
      required: true,
      min: 0,
    },
    {
      name: "description",
      labelKey: "resource.billingGroups.field.description",
      type: "textarea",
    },
    {
      name: "enabled",
      labelKey: "resource.billingGroups.field.enabled",
      type: "boolean",
    },
  ] satisfies BillingGroupField[],
} as const;
