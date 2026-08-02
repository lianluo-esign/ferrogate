import { GLOBAL_FLAGS } from "../global-args.js";
/**
 * `ferrogate ops status`.
 *
 * Port of `ferrogate-cli::ctl::ops_cmd` (inventory-edge-control.md §1.1): a
 * top-level convenience over the shared typed client, taking the same global
 * args as `ctl`. It is implemented by delegating to the registry dispatcher for
 * `system status`, so the precedence, action identity, render gate, and
 * diagnostics are literally the same code path — a divergence here would be a
 * second, untested client.
 */
import type { CommandNode } from "../runtime.js";
import { runResource } from "./ctl.js";

export const opsCommand: CommandNode = {
  name: "ops",
  about: "Operational status",
  sub: [
    {
      name: "status",
      about: "Show Control Plane API status",
      flags: GLOBAL_FLAGS,
      runRaw: async (runtime, argv) => runResource(runtime, ["system", "status", ...argv]),
    },
  ],
};
