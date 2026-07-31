/**
 * `@ferrogate/routing` — canary / shadow traffic bucketing.
 *
 * Replaces the Rust crate `ferrogate-routing`. Pure, deterministic assignment;
 * no I/O.
 */
import type { Scope } from "@ferrogate/core";

/** How a bucketed request is treated relative to the primary target. */
export type RouteStrategy = "primary" | "canary" | "shadow";

/** The resolved routing decision for one request. */
export interface RouteDecision {
  strategy: RouteStrategy;
  target: string;
}

/** Deterministically assigns a stable key to a routing strategy. */
export interface Bucketing {
  assign(key: string, scope: Scope): RouteDecision;
}
