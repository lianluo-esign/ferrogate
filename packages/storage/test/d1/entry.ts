/**
 * Test-only Worker entry for the D1 suite's `wrangler.toml`.
 *
 * `@ferrogate/storage` is a library and ships no Worker, but workerd resolves a
 * `[[durable_objects.bindings]]` `class_name` against the ENTRY module's NAMED
 * exports — a class merely reachable through an import graph is not found and
 * the isolate refuses to start. So the D1 suite needs an entry module for the
 * same reason `test/do/entry.ts` exists, and it needs its OWN rather than
 * borrowing that one: `test/do/entry.ts` also exports `FaultyTenantDataObject`,
 * whose whole purpose is to fail its schema apply, and a namespace that exists
 * only to be broken has no business being reachable from the suite that proves
 * the money paths work.
 *
 * THIS FILE PROVES NOTHING ABOUT THE DEPLOYED WORKER. The production line lives
 * in `apps/gateway/src/worker.ts` and is gated by
 * `apps/gateway/test/wrangler-bindings.test.ts`.
 */
import { TenantDataObject } from "../../src/tenant-data-object.js";

export { TenantDataObject };

export default {
  fetch(): Response {
    // The suite drives the namespace through its binding, never over HTTP;
    // workerd still requires the entry module to export a handler.
    return new Response("storage d1 test worker", { status: 200 });
  },
} satisfies ExportedHandler;
