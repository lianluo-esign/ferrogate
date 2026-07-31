/**
 * `@ferrogate/guardrails` — content/tool guardrail policy evaluation.
 *
 * Replaces the Rust crate `ferrogate-guardrails`. On Cloudflare this delegates
 * to AI Gateway guardrails and Workers AI where a managed check exists.
 */
import { z } from "zod";
import type { Scope } from "@ferrogate/core";

/** Terminal verdict of a guardrail evaluation. */
export const guardrailVerdictSchema = z.enum(["allow", "deny", "flag"]);
export type GuardrailVerdict = z.infer<typeof guardrailVerdictSchema>;

/** A versioned guardrail policy bound to a tenancy scope. */
export interface GuardrailPolicy {
  id: string;
  scope: Scope;
  revision: number;
}

/** Result of evaluating input/output against a policy. */
export interface GuardrailEvaluation {
  verdict: GuardrailVerdict;
  policyId: string;
  reason?: string;
}

/** Evaluates request/response payloads against active policies. */
export interface GuardrailEngine {
  evaluate(policy: GuardrailPolicy, payload: unknown): Promise<GuardrailEvaluation>;
}
