/**
 * Test scaffolding: an in-memory scripted {@link HttpTransport} (the TS analogue
 * of the Rust `MockTransport`) and route builders mirroring the Rust
 * `read_routes` / `ok_envelope` helpers. No live network.
 */
import type {
  HttpRequest,
  HttpResponse,
  HttpTransport,
} from "../src/cloudflare-client.js";
import {
  CloudflareClient,
  CloudflareConfig,
  EnvTokenResolver,
} from "../src/cloudflare-client.js";
import { CloudflareSecretResolver } from "../src/cloudflare.js";

export const BASE =
  "https://api.test/client/v4/accounts/acct-123/secrets_store";

/** Wrap a JSON `result` in a Cloudflare success envelope. */
export function okEnvelope(resultJson: string): string {
  return `{"success":true,"errors":[],"messages":[],"result":${resultJson}}`;
}

/** A scripted transport keyed on `"{METHOD} {url}"`. Unscripted → loud error. */
export class MockTransport implements HttpTransport {
  constructor(private readonly routes: Map<string, [number, string]>) {}
  execute(request: HttpRequest): Promise<HttpResponse> {
    const key = `${request.method} ${request.url}`;
    const hit = this.routes.get(key);
    if (hit !== undefined) {
      return Promise.resolve({ status: hit[0], body: hit[1] });
    }
    return Promise.resolve({
      status: 404,
      body: `{"success":false,"errors":[{"code":0,"message":"unscripted request ${key}"}],"result":null}`,
    });
  }
}

/** Build a resolver whose client speaks to the scripted transport. */
export function resolverWith(
  routes: Map<string, [number, string]>,
): CloudflareSecretResolver {
  const config = new CloudflareConfig(
    "acct-123",
    "inline-token",
    "https://api.test/client/v4",
  );
  const client = new CloudflareClient(
    config,
    new EnvTokenResolver({}),
    new MockTransport(routes),
  );
  return CloudflareSecretResolver.fromClient(client);
}

/** One store `provider-keys` (id `store-1`) holding secret `openai-api-key`. */
export function readRoutes(): Map<string, [number, string]> {
  return new Map<string, [number, string]>([
    [
      `GET ${BASE}/stores`,
      [200, okEnvelope(`[{"id":"store-1","name":"provider-keys"}]`)],
    ],
    [
      `GET ${BASE}/stores/store-1/secrets`,
      [200, okEnvelope(`[{"id":"sec-1","name":"openai-api-key"}]`)],
    ],
  ]);
}

/** JSON array of `count` secret metadata items `bulk-0 … bulk-{count-1}`. */
export function secretsListingJson(count: number): string {
  const items: string[] = [];
  for (let i = 0; i < count; i++) {
    items.push(`{"id":"sec-${i}","name":"bulk-${i}"}`);
  }
  return `[${items.join(",")}]`;
}
