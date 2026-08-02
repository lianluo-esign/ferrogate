/**
 * Test-only Worker entry.
 *
 * workerd resolves a `[[durable_objects.bindings]]` `class_name` against the
 * ENTRY module's named exports — a class that is merely reachable through an
 * import graph is NOT found, and the isolate refuses to start with
 * "Durable Object class ShadowBudgetDurableObject not found". This file is the
 * fixture that satisfies that constraint for the test suite; in production the
 * same line goes in `apps/gateway/src/worker.ts`.
 */
export { ShadowBudgetDurableObject } from "../../src/shadow-budget-do.js";

export default {
  fetch(): Response {
    // The suite drives the DO through its binding, never over HTTP; workerd
    // still requires the entry to export a handler.
    return new Response("routing test worker", { status: 200 });
  },
} satisfies ExportedHandler;
