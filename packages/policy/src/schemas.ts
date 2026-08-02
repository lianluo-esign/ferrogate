/**
 * Zod wire schemas for the policy value types (inventory §2.8).
 *
 * These validate the serialisable shapes at trust boundaries (e.g. a policy
 * config read from D1 / an admin API). The runtime decision functions operate on
 * the plain TS types; these schemas parse untrusted input into them.
 */
import { z } from "zod";

/** Scope kinds (Rust `QuotaScopeKind`). */
export const quotaScopeKindSchema = z.enum(["tenant", "project", "workspace", "key"]);

/** The winning-scope selector recorded per quota dimension. */
export const quotaScopeSelectorSchema = z.object({
  kind: quotaScopeKindSchema,
  id: z.string(),
});

/** The merged effective quota (serialisable projection). */
export const effectiveQuotaSchema = z.object({
  modelAllowlist: z.array(z.string()).optional(),
  rpmLimit: z.number().int().nonnegative().optional(),
  rpmLimitScope: quotaScopeSelectorSchema.optional(),
  tpmLimit: z.number().int().nonnegative().optional(),
  tpmLimitScope: quotaScopeSelectorSchema.optional(),
  monthlyBudgetUsd: z.number().nonnegative().optional(),
  monthlyBudgetScope: quotaScopeSelectorSchema.optional(),
  agentCostBudgetUsd: z.number().nonnegative().optional(),
  agentCostBudgetScope: quotaScopeSelectorSchema.optional(),
  assetStorageQuotaBytes: z.number().int().nonnegative().optional(),
  assetMaxObjectBytes: z.number().int().nonnegative().optional(),
  monthlyEgressBytesBudget: z.number().int().nonnegative().optional(),
  monthlyEgressBytesScope: quotaScopeSelectorSchema.optional(),
  downloadRpmLimit: z.number().int().nonnegative().optional(),
  downloadRpmLimitScope: quotaScopeSelectorSchema.optional(),
  deniedBy: quotaScopeKindSchema.optional(),
});

/** Workflow-budget caps expressed by config (#279). */
export const workflowBudgetCapsSchema = z.object({
  costBudgetCredits: z.number().int().optional(),
  tokenBudget: z.number().int().optional(),
  toolCallBudget: z.number().int().optional(),
  wallClockMillis: z.number().int().nonnegative().optional(),
});

/** A policy subject (each field absent ⇒ wildcard). */
export const policySubjectSchema = z.object({
  organizationId: z.string().optional(),
  projectId: z.string().optional(),
  apiKeyId: z.string().optional(),
});

/** A single deny rule. */
export const policyRuleSchema = z.object({
  subject: policySubjectSchema,
  models: z.array(z.string()),
  providers: z.array(z.string()),
  code: z.string(),
  message: z.string(),
});
