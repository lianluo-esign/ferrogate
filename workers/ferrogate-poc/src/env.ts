// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-31
// description: Token4AI Cloud, FerroGate AI Gateway, the binding surface of the
// #424 Cloudflare Containers PoC Worker. Kept in one file so the deployable
// entrypoint and the docker-free workerd harness agree on exactly one Env shape.

import type { Container } from "@cloudflare/containers";

/**
 * Bindings the PoC declares.
 *
 * `wrangler types` would generate a superset of this from `wrangler.toml`; it is
 * written by hand instead so the repository typechecks with no `wrangler`
 * invocation and no generated file that can silently drift out of the tree.
 * `scripts/check-workers.sh` runs `tsc --noEmit` against exactly these types.
 */
export interface PocEnv {
  /**
   * The Durable Object namespace fronting the container class. Present only in a
   * real Cloudflare deployment: miniflare cannot provide a container-backed DO
   * without Docker, which is why the harness entrypoint never touches it.
   */
  FERROGATE?: DurableObjectNamespace<Container<PocEnv>>;

  /**
   * The KV namespace the §6 shim probe reads. This is the binding the container
   * itself cannot hold: it is resolved Worker-side, inside the outbound handler,
   * and only the resulting bytes cross into the sandbox.
   */
  POC_KV?: KVNamespace;

  /**
   * Harness-only: the base URL of a locally spawned `ferrogate run`.
   *
   * Set by `vitest.config.ts` so the workerd suite can drive the *same*
   * forwarding code the deployed Worker runs without a container binding. Unset
   * in a real deployment, where the origin is reached through `FERROGATE`.
   */
  FERROGATE_ORIGIN_URL?: string;
}
