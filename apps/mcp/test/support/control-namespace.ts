/**
 * Zero-D1 S5 (#881) test support: the real `CONTROL_DATA` namespace this mcp
 * suite is provisioned with (cross-script from the gateway aux worker). Tests
 * that used to inject a `DB`/`BILLING_DB` control handle into `resolvePorts`
 * now also pass `CONTROL_DATA`, which the seam reads.
 */
import { env } from "cloudflare:test";

export function controlNamespace(): unknown {
  return (env as unknown as { CONTROL_DATA: unknown }).CONTROL_DATA;
}
