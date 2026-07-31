// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-31
// description: Token4AI Cloud, FerroGate AI Gateway, port brokering for the #424
// docker-free PoC harness. `process.env` is the single source of truth because
// vitest.config.ts and the globalSetup module are transformed separately and
// cannot rely on sharing a module instance -- two independently randomised port
// pairs would point the Worker at a gateway that was never started.

import { createServer } from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

const testDir = path.dirname(fileURLToPath(import.meta.url));

/** Repository root, used to find `target/{debug,release}/ferrogate`. */
export const REPO_ROOT = path.resolve(testDir, "../../..");

const GATEWAY_PORT_VAR = "FERROGATE_POC_GATEWAY_PORT";
const UPSTREAM_PORT_VAR = "FERROGATE_POC_UPSTREAM_PORT";

/**
 * Reserve two loopback ports and publish them on `process.env`.
 *
 * Called from `vitest.config.ts` before the pool starts, so the miniflare
 * binding and the spawned gateway agree. Idempotent: a second call returns the
 * already-published pair rather than re-randomising.
 */
export async function ensurePorts(): Promise<{ gateway: number; upstream: number }> {
  if (!process.env[GATEWAY_PORT_VAR]) {
    process.env[GATEWAY_PORT_VAR] = String(await reserveEphemeralPort());
  }
  if (!process.env[UPSTREAM_PORT_VAR]) {
    process.env[UPSTREAM_PORT_VAR] = String(await reserveEphemeralPort());
  }
  return { gateway: gatewayPort(), upstream: upstreamPort() };
}

export function gatewayPort(): number {
  return requirePort(GATEWAY_PORT_VAR);
}

export function upstreamPort(): number {
  return requirePort(UPSTREAM_PORT_VAR);
}

function requirePort(name: string): number {
  const raw = process.env[name];
  const port = Number.parseInt(raw ?? "", 10);
  if (!Number.isInteger(port) || port <= 0) {
    // Loud, not defaulted. A silently defaulted port would make the harness
    // proxy to whatever else happens to be listening there.
    throw new Error(`ferrogate-poc harness: ${name} is not set; ensurePorts() did not run`);
  }
  return port;
}

/**
 * Ask the OS for a free port and immediately release it.
 *
 * There is an unavoidable window between release and re-bind; the repo hit the
 * same race in Rust (`ai_proxy_runtime` port contention). Nothing here retries
 * it, because a bind failure surfaces as a named gateway-start error rather than
 * as a wrong-looking assertion.
 */
function reserveEphemeralPort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (address === null || typeof address === "string") {
        server.close(() => reject(new Error("ferrogate-poc harness: could not reserve a port")));
        return;
      }
      const { port } = address;
      server.close(() => resolve(port));
    });
  });
}
