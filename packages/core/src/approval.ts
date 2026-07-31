/**
 * Approval policy — port of `ferrogate-core::ApprovalPolicy`.
 *
 * Rust: `enum ApprovalPolicy { Never (default), Always }` with
 * `#[serde(rename_all = "snake_case")]`, so the wire form is `"never"` /
 * `"always"` and the default is `"never"`.
 */
import { z } from "zod";

/** Zod validator for the snake_case wire form of `ApprovalPolicy`. */
export const approvalPolicySchema = z.enum(["never", "always"]);

/** Approval policy attached to a tool or MCP binding. */
export type ApprovalPolicy = z.infer<typeof approvalPolicySchema>;

/** The Rust `#[default]` variant (`ApprovalPolicy::Never`). */
export const DEFAULT_APPROVAL_POLICY: ApprovalPolicy = "never";
