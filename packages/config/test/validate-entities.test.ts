/**
 * Table-driven port checks for the entity-list validators of
 * `Config::validate()` (`validate_providers`, `validate_models`,
 * `validate_mcp_servers`, `validate_api_keys`, `validate_policies`,
 * `validate_gateway_configs`, `validate_agent_upstreams`, `validate_upstreams`,
 * `validate_routes`).
 *
 * Every case asserts the EXACT `field <path>: <reason>` the Rust `bail!`
 * produces — the field path is the load-bearing half (it is what tells an
 * operator which line to edit), so `toThrow()` alone would prove nothing.
 */
import { describe, expect, test } from "vitest";
import { configSchema } from "../src/schema/config.js";
import { validateConfig } from "../src/validate.js";

/** Run the real gate and return the first error message, or fail loudly. */
function firstError(raw: Record<string, unknown>): string {
  const config = configSchema.parse(raw);
  try {
    validateConfig(config);
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
  throw new Error("expected validateConfig to reject this config, but it passed");
}

/** Assert the gate accepts a config (throws the real error if it does not). */
function expectAccepted(raw: Record<string, unknown>): void {
  validateConfig(configSchema.parse(raw));
}

const provider = (extra: Record<string, unknown> = {}) => ({
  name: "openai",
  base_url: "https://api.openai.com/v1",
  ...extra,
});
const model = (extra: Record<string, unknown> = {}) => ({
  name: "gpt",
  provider: "openai",
  provider_model: "gpt-4o",
  ...extra,
});
const apiKey = (extra: Record<string, unknown> = {}) => ({
  id: "k1",
  name: "k1",
  key_env: "K1",
  platform_operator: true,
  ...extra,
});
// `command` is required for the stdio transport (`validate_mcp_server_config`),
// so the baseline fixture carries one and every network-transport case overrides
// `transport`/`url`.
const mcpServer = (extra: Record<string, unknown> = {}) => ({
  name: "srv",
  transport: "stdio",
  command: "/usr/bin/srv",
  tools_to_execute: ["echo"],
  ...extra,
});

/** A `shared_headers` server: the auth mode requires at least one static header. */
const sharedHeader = [{ name: "Authorization", value: "Bearer token" }];

describe("validate_providers", () => {
  const cases: [string, Record<string, unknown>, string][] = [
    [
      "blank name",
      { providers: [provider({ name: "  " })] },
      "field providers[0].name: cannot be empty",
    ],
    [
      "duplicate name",
      { providers: [provider(), provider()] },
      "field providers[1].name: duplicate provider name openai",
    ],
    [
      "blank base_url",
      { providers: [provider({ base_url: "" })] },
      "field providers[0].base_url: cannot be empty",
    ],
    [
      "empty api_key_env",
      { providers: [provider({ api_key_env: "" })] },
      "field providers[0].api_key_env: cannot be empty",
    ],
    [
      "unsupported secret_ref scheme",
      { providers: [provider({ secret_ref: "http://vault/x" })] },
      "field providers[0].secret_ref: unsupported secret reference scheme " +
        "(expected env://, vault://, cf://, or byok://): http://vault/x",
    ],
    [
      "vault secret_ref without #field",
      { providers: [provider({ secret_ref: "vault://secret/data/openai" })] },
      "field providers[0].secret_ref: vault:// secret reference requires a #field suffix, " +
        "e.g. vault://secret/data/openai#api_key (got vault://secret/data/openai)",
    ],
    [
      "bedrock without an access key id",
      {
        providers: [
          provider({ kind: "bedrock", aws_secret_access_key_env: "S", region: "us-east-1" }),
        ],
      },
      "field providers[0].aws_access_key_id: required when kind = bedrock",
    ],
    [
      "bedrock without a region",
      {
        providers: [
          provider({ kind: "aws-bedrock", aws_access_key_id: "A", aws_secret_access_key_env: "S" }),
        ],
      },
      "field providers[0].region: required when kind = bedrock (this is the AWS region, e.g. us-east-1)",
    ],
    [
      "vertex without a project id",
      {
        providers: [provider({ kind: "vertex", gcp_access_token_env: "T", region: "us-central1" })],
      },
      "field providers[0].gcp_project_id: required when kind = vertex",
    ],
    [
      "vertex without a region",
      {
        providers: [
          provider({ kind: "vertex-ai", gcp_project_id: "p", gcp_access_token_env: "T" }),
        ],
      },
      "field providers[0].region: required when kind = vertex (this is the GCP location, e.g. us-central1)",
    ],
  ];
  test.each(cases)("rejects %s", (_name, raw, expected) => {
    expect(firstError(raw)).toBe(expected);
  });

  test("accepts a fully-specified provider set", () => {
    expectAccepted({
      providers: [
        provider({ secret_ref: "env://OPENAI_API_KEY", region: "us-east-1" }),
        provider({
          name: "bedrock",
          kind: "bedrock",
          aws_access_key_id: "A",
          aws_secret_access_key_env: "S",
          region: "us-east-1",
        }),
        provider({ name: "cf", secret_ref: "cf://provider-keys/openai-api-key" }),
      ],
    });
  });
});

describe("validate_models", () => {
  const withProvider = (
    models: Record<string, unknown>[],
    extra: Record<string, unknown> = {},
  ) => ({
    providers: [provider()],
    models,
    ...extra,
  });
  const cases: [string, Record<string, unknown>, string][] = [
    ["blank name", withProvider([model({ name: " " })]), "field models[0].name: cannot be empty"],
    [
      "duplicate name",
      withProvider([model(), model()]),
      "field models[1].name: duplicate model name gpt",
    ],
    [
      "unknown provider",
      withProvider([model({ provider: "nope" })]),
      "field models[0].provider: model gpt references unknown provider nope",
    ],
    [
      "blank provider_model",
      withProvider([model({ provider_model: "" })]),
      "field models[0].provider_model: cannot be empty",
    ],
    [
      "lowest_cost without prices",
      withProvider([model({ routing_strategy: "lowest_cost" })]),
      "field models[0].routing_strategy: lowest_cost requires input_price_per_1m and " +
        "output_price_per_1m on the primary model",
    ],
    [
      "billing_service enabled without a gateway-side price (#146)",
      withProvider([model()], { billing_service: { enabled: true } }),
      "field models[0]: billing_service.enabled requires input_price_per_1m and " +
        "output_price_per_1m on every model, so monthly budget enforcement never diverges from " +
        "the billing service's ledger (model gpt)",
    ],
    [
      "fallback on an unknown provider",
      withProvider([model({ fallbacks: [{ provider: "nope", provider_model: "x" }] })]),
      "field models[0].fallbacks[0].provider: model gpt references unknown fallback provider nope",
    ],
    [
      "fallback weight zero",
      withProvider([
        model({ fallbacks: [{ provider: "openai", provider_model: "x", weight: 0 }] }),
      ]),
      "field models[0].fallbacks[0].weight: must be greater than zero",
    ],
    [
      "canary percent above 100",
      withProvider([model({ canary: { provider: "openai", provider_model: "x", percent: 101 } })]),
      "field models[0].canary.percent: must be between 0 and 100 (got 101)",
    ],
    [
      "shadow on an unknown provider",
      withProvider([model({ shadow: { provider: "nope", provider_model: "x" } })]),
      "field models[0].shadow.provider: model gpt references unknown shadow provider nope",
    ],
    [
      "shadow sample percent above 100",
      withProvider([
        model({ shadow: { provider: "openai", provider_model: "x", sample_percent: 200 } }),
      ]),
      "field models[0].shadow.sample_percent: must be between 0 and 100 (got 200)",
    ],
  ];
  test.each(cases)("rejects %s", (_name, raw, expected) => {
    expect(firstError(raw)).toBe(expected);
  });

  test("a DISABLED fallback is not cross-checked (Rust skips it)", () => {
    expectAccepted(
      withProvider([
        model({ fallbacks: [{ provider: "nope", provider_model: "", enabled: false }] }),
      ]),
    );
  });

  test("accepts priced models when the billing service is enabled", () => {
    expectAccepted(
      withProvider(
        [
          model({
            routing_strategy: "lowest_cost",
            input_price_per_1m: 1,
            output_price_per_1m: 2,
            fallbacks: [
              {
                provider: "openai",
                provider_model: "gpt-4o-mini",
                input_price_per_1m: 0.5,
                output_price_per_1m: 1,
              },
            ],
          }),
        ],
        { billing_service: { enabled: true } },
      ),
    );
  });
});

describe("validate_mcp_servers", () => {
  const cases: [string, Record<string, unknown>, string][] = [
    [
      "duplicate server name",
      { mcp_servers: [mcpServer(), mcpServer()] },
      "field mcp_servers[1].name: duplicate MCP server name srv",
    ],
    [
      "blank name",
      { mcp_servers: [mcpServer({ name: " " })] },
      "field mcp_servers[0]: MCP server name cannot be empty",
    ],
    [
      "a dash in the name (tool names are serverName-toolName)",
      { mcp_servers: [mcpServer({ name: "my-srv" })] },
      "field mcp_servers[0]: MCP server name cannot contain '-' because tool names use serverName-toolName",
    ],
    [
      "empty tools_to_execute (execution is deny-by-default)",
      { mcp_servers: [mcpServer({ tools_to_execute: [] })] },
      "field mcp_servers[0]: MCP server srv must set tools_to_execute; execution is deny-by-default",
    ],
    [
      "a network transport with no url",
      { mcp_servers: [mcpServer({ transport: "streamable_http" })] },
      "field mcp_servers[0]: MCP network server srv requires url",
    ],
    [
      "a Cloudflare managed server over http (issue #408)",
      {
        mcp_servers: [
          mcpServer({
            transport: "streamable_http",
            url: "http://acme.mcp.cloudflare.com/sse",
            auth_type: "shared_headers",
            headers: sharedHeader,
          }),
        ],
      },
      "field mcp_servers[0].url: Cloudflare managed MCP server srv must use an https url",
    ],
    [
      "an unauthenticated Cloudflare managed server (issue #408)",
      {
        mcp_servers: [
          mcpServer({
            transport: "sse",
            url: "https://acme.mcp.cloudflare.com/sse",
            auth_type: "none",
          }),
        ],
      },
      "field mcp_servers[0].auth_type: Cloudflare managed MCP server srv requires authentication " +
        "(shared_headers with a Cloudflare API bearer token, per_user_oauth, or " +
        "original_bearer); Cloudflare rejects unauthenticated requests",
    ],
    [
      // `is_cloudflare_managed_mcp_url` matches a tenant Worker on BOTH the
      // conventional `/mcp` and `/sse` paths, not just `/mcp`.
      "an unauthenticated tenant workers.dev MCP endpoint on /mcp (issue #408)",
      {
        mcp_servers: [
          mcpServer({ transport: "streamable_http", url: "https://tenant.workers.dev/mcp/" }),
        ],
      },
      "field mcp_servers[0].auth_type: Cloudflare managed MCP server srv requires authentication " +
        "(shared_headers with a Cloudflare API bearer token, per_user_oauth, or " +
        "original_bearer); Cloudflare rejects unauthenticated requests",
    ],
    [
      "an unauthenticated tenant workers.dev MCP endpoint on /sse (issue #408)",
      {
        mcp_servers: [mcpServer({ transport: "sse", url: "https://tenant.workers.dev/agent/sse" })],
      },
      "field mcp_servers[0].auth_type: Cloudflare managed MCP server srv requires authentication " +
        "(shared_headers with a Cloudflare API bearer token, per_user_oauth, or " +
        "original_bearer); Cloudflare rejects unauthenticated requests",
    ],
  ];
  test.each(cases)("rejects %s", (_name, raw, expected) => {
    expect(firstError(raw)).toBe(expected);
  });

  test("an ordinary workers.dev Worker is NOT treated as a managed MCP upstream", () => {
    // Neither `/mcp` nor `/sse`: the #408 https+auth guardrails must not apply.
    expectAccepted({
      mcp_servers: [
        mcpServer({ transport: "streamable_http", url: "http://tenant.workers.dev/api/rpc" }),
      ],
    });
  });

  test("accepts an authenticated https Cloudflare managed server", () => {
    expectAccepted({
      mcp_servers: [
        mcpServer({
          transport: "streamable_http",
          url: "https://acme.mcp.cloudflare.com/sse",
          auth_type: "shared_headers",
          headers: sharedHeader,
        }),
      ],
    });
  });
});

/**
 * `ferrogate_mcp::validate_mcp_server_config` — the legs a previous wave left as
 * a PORT-TODO (reconnect bounds, auth-mode/static-header pairing, OAuth config
 * and the stdio `command` requirement), now ported. Every case pins the exact
 * `field mcp_servers[0]: <Rust reason>`.
 */
describe("validate_mcp_server_config (ported from @ferrogate/mcp)", () => {
  const oauth = {
    issuer: "https://idp.example",
    client_id: "cid",
    client_secret_ref: "env://MCP_OAUTH_SECRET",
    redirect_uri: "https://gw.example/callback",
  };
  const httpServer = (extra: Record<string, unknown> = {}) =>
    mcpServer({ transport: "streamable_http", url: "https://srv.example/rpc", ...extra });

  const cases: [string, Record<string, unknown>, string][] = [
    // --- reconnect bounds ---
    [
      "max_reconnect_attempts of zero",
      { mcp_servers: [mcpServer({ max_reconnect_attempts: 0 })] },
      "field mcp_servers[0]: MCP server srv max_reconnect_attempts must be greater than 0",
    ],
    [
      "a zero min reconnect backoff",
      { mcp_servers: [mcpServer({ min_reconnect_backoff_secs: 0 })] },
      "field mcp_servers[0]: MCP server srv reconnect backoff values must be greater than 0",
    ],
    [
      "a zero max reconnect backoff",
      { mcp_servers: [mcpServer({ max_reconnect_backoff_secs: 0 })] },
      "field mcp_servers[0]: MCP server srv reconnect backoff values must be greater than 0",
    ],
    [
      "a min reconnect backoff above the max",
      { mcp_servers: [mcpServer({ min_reconnect_backoff_secs: 31 })] },
      "field mcp_servers[0]: MCP server srv min reconnect backoff cannot exceed max",
    ],
    // --- auth modes ---
    [
      "the unimplemented oauth auth mode",
      { mcp_servers: [mcpServer({ auth_type: "oauth" })] },
      "field mcp_servers[0]: MCP auth_type oauth is not implemented; use per_user_oauth for " +
        "user-isolated OAuth or shared_headers for shared credentials",
    ],
    [
      "the unimplemented per_user_headers auth mode",
      { mcp_servers: [mcpServer({ auth_type: "per_user_headers" })] },
      "field mcp_servers[0]: MCP auth_type per_user_headers is not implemented; use " +
        "per_user_oauth, original_bearer, or ferrogate_signed_jwt",
    ],
    [
      "shared_headers with no static header",
      { mcp_servers: [mcpServer({ auth_type: "shared_headers" })] },
      "field mcp_servers[0]: MCP auth_type shared_headers requires at least one static header",
    ],
    [
      "static headers under auth_type none",
      { mcp_servers: [mcpServer({ headers: sharedHeader })] },
      "field mcp_servers[0]: MCP static headers require auth_type shared_headers",
    ],
    [
      "per_user_oauth without an oauth block",
      { mcp_servers: [mcpServer({ auth_type: "per_user_oauth" })] },
      "field mcp_servers[0]: MCP auth_type per_user_oauth requires oauth configuration",
    ],
    [
      "original_bearer without an oauth block",
      { mcp_servers: [mcpServer({ auth_type: "original_bearer" })] },
      "field mcp_servers[0]: MCP auth_type original_bearer requires oauth configuration",
    ],
    [
      "ferrogate_signed_jwt without an audience",
      { mcp_servers: [mcpServer({ auth_type: "ferrogate_signed_jwt" })] },
      "field mcp_servers[0]: MCP auth_type ferrogate_signed_jwt requires signed_jwt_audience",
    ],
    [
      "static headers under a per-user identity mode",
      {
        mcp_servers: [
          mcpServer({
            auth_type: "ferrogate_signed_jwt",
            signed_jwt_audience: "a",
            headers: sharedHeader,
          }),
        ],
      },
      "field mcp_servers[0]: per-user MCP identity modes cannot define static headers",
    ],
    // --- oauth config ---
    [
      "a non-URL oauth issuer",
      {
        mcp_servers: [
          mcpServer({ auth_type: "original_bearer", oauth: { ...oauth, issuer: "idp" } }),
        ],
      },
      "field mcp_servers[0]: MCP oauth.issuer is invalid",
    ],
    [
      "a non-http(s) oauth issuer",
      {
        mcp_servers: [
          mcpServer({
            auth_type: "original_bearer",
            oauth: { ...oauth, issuer: "ftp://idp.example" },
          }),
        ],
      },
      "field mcp_servers[0]: MCP oauth.issuer must be an http or https URL",
    ],
    [
      "a plaintext oauth issuer without allow_insecure_http",
      {
        mcp_servers: [
          mcpServer({
            auth_type: "original_bearer",
            oauth: { ...oauth, issuer: "http://idp.example" },
          }),
        ],
      },
      "field mcp_servers[0]: MCP oauth.issuer must use https unless allow_insecure_http is " +
        "explicitly enabled",
    ],
    [
      "a blank oauth client_id",
      {
        mcp_servers: [
          mcpServer({ auth_type: "original_bearer", oauth: { ...oauth, client_id: " " } }),
        ],
      },
      "field mcp_servers[0]: MCP oauth.client_id cannot be empty",
    ],
    [
      "an empty oauth scope list",
      {
        mcp_servers: [mcpServer({ auth_type: "original_bearer", oauth: { ...oauth, scopes: [] } })],
      },
      "field mcp_servers[0]: MCP oauth.scopes must contain non-empty values",
    ],
    [
      "a blank oauth scope",
      {
        mcp_servers: [
          mcpServer({ auth_type: "original_bearer", oauth: { ...oauth, scopes: ["openid", " "] } }),
        ],
      },
      "field mcp_servers[0]: MCP oauth.scopes must contain non-empty values",
    ],
    [
      "per_user_oauth without a client_secret_ref",
      {
        mcp_servers: [
          mcpServer({ auth_type: "per_user_oauth", oauth: { ...oauth, client_secret_ref: null } }),
        ],
      },
      "field mcp_servers[0]: MCP per_user_oauth requires oauth.client_secret_ref",
    ],
    [
      "per_user_oauth without a redirect_uri",
      {
        mcp_servers: [
          mcpServer({ auth_type: "per_user_oauth", oauth: { ...oauth, redirect_uri: null } }),
        ],
      },
      "field mcp_servers[0]: MCP per_user_oauth requires oauth.redirect_uri",
    ],
    // --- static headers ---
    [
      "a malformed static header name",
      {
        mcp_servers: [
          mcpServer({ auth_type: "shared_headers", headers: [{ name: "bad header", value: "v" }] }),
        ],
      },
      "field mcp_servers[0]: MCP static header name is invalid",
    ],
    [
      "a protocol-owned static header",
      {
        mcp_servers: [
          mcpServer({
            auth_type: "shared_headers",
            headers: [{ name: "Mcp-Session-Id", value: "v" }],
          }),
        ],
      },
      "field mcp_servers[0]: MCP static header Mcp-Session-Id is protocol-owned",
    ],
    [
      "a static header setting both value and value_env",
      {
        mcp_servers: [
          mcpServer({
            auth_type: "shared_headers",
            headers: [{ name: "X-Key", value: "v", value_env: "E" }],
          }),
        ],
      },
      "field mcp_servers[0]: MCP static header must set exactly one of value or value_env",
    ],
    [
      "a static header setting neither value nor value_env",
      { mcp_servers: [mcpServer({ auth_type: "shared_headers", headers: [{ name: "X-Key" }] })] },
      "field mcp_servers[0]: MCP static header must set exactly one of value or value_env",
    ],
    [
      "a static header with a blank value_env",
      {
        mcp_servers: [
          mcpServer({ auth_type: "shared_headers", headers: [{ name: "X-Key", value_env: " " }] }),
        ],
      },
      "field mcp_servers[0]: MCP static header must set exactly one of value or value_env",
    ],
    [
      "a control character in a static header value",
      {
        mcp_servers: [
          mcpServer({
            auth_type: "shared_headers",
            headers: [{ name: "X-Key", value: `a${String.fromCharCode(1)}b` }],
          }),
        ],
      },
      "field mcp_servers[0]: MCP static header value is invalid",
    ],
    // --- transports ---
    [
      "a non-http(s) network endpoint",
      { mcp_servers: [httpServer({ url: "ftp://srv.example/rpc" })] },
      "field mcp_servers[0]: MCP network transports require http or https url",
    ],
    [
      "a scheme-less network endpoint",
      { mcp_servers: [httpServer({ url: "/rpc" })] },
      "field mcp_servers[0]: MCP network transports require http or https url",
    ],
    [
      "a whitespace-bearing network endpoint",
      { mcp_servers: [httpServer({ url: "https://srv example/rpc" })] },
      "field mcp_servers[0]: invalid MCP endpoint https://srv example/rpc",
    ],
    [
      "a stdio server with no command",
      { mcp_servers: [mcpServer({ command: null })] },
      "field mcp_servers[0]: MCP stdio server srv requires command",
    ],
    [
      "a stdio server with an empty command",
      { mcp_servers: [mcpServer({ command: "" })] },
      "field mcp_servers[0]: MCP stdio server srv requires command",
    ],
  ];
  test.each(cases)("rejects %s", (_name, raw, expected) => {
    expect(firstError(raw)).toBe(expected);
  });

  test("accepts a fully-specified per_user_oauth network server", () => {
    expectAccepted({ mcp_servers: [httpServer({ auth_type: "per_user_oauth", oauth })] });
  });

  test("accepts a shared_headers network server with a value_env header", () => {
    expectAccepted({
      mcp_servers: [
        httpServer({
          auth_type: "shared_headers",
          headers: [{ name: "X-Key", value_env: "MCP_KEY" }],
        }),
      ],
    });
  });

  test("accepts a ferrogate_signed_jwt server and a plain stdio server", () => {
    expectAccepted({
      mcp_servers: [
        httpServer({ auth_type: "ferrogate_signed_jwt", signed_jwt_audience: "gw" }),
        mcpServer({ name: "local" }),
      ],
    });
  });

  test("accepts a plaintext oauth issuer once allow_insecure_http is explicit", () => {
    expectAccepted({
      mcp_servers: [
        httpServer({
          auth_type: "original_bearer",
          oauth: { ...oauth, issuer: "http://idp.example", allow_insecure_http: true },
        }),
      ],
    });
  });

  test("accepts the legacy `headers` alias for auth_type shared_headers", () => {
    const parsed = configSchema.parse({
      mcp_servers: [httpServer({ auth_type: "headers", headers: sharedHeader })],
    });
    expect((parsed.mcp_servers[0] as NonNullable<(typeof parsed.mcp_servers)[0]>).auth_type).toBe(
      "shared_headers",
    );
    validateConfig(parsed);
  });

  /**
   * PLATFORM LIMIT (kept as a PORT-TODO in src/validate/entities.ts): a Worker
   * has no filesystem to read `tls.ca_cert_path` from and `fetch()` exposes no
   * hook for a custom CA root or for skipping verification. The approximation is
   * to REJECT rather than silently ignore — this pins that choice.
   */
  describe("mcp tls is rejected, not silently ignored", () => {
    test("ca_cert_path", () => {
      expect(
        firstError({ mcp_servers: [httpServer({ tls: { ca_cert_path: "/etc/ca.pem" } })] }),
      ).toBe(
        "field mcp_servers[0]: MCP server srv: MCP tls.ca_cert_path is unsupported on Cloudflare " +
          "Workers: there is no filesystem to read the PEM from and fetch() exposes no hook to add " +
          "a custom CA root",
      );
    });
    test("insecure_skip_verify", () => {
      expect(
        firstError({ mcp_servers: [httpServer({ tls: { insecure_skip_verify: true } })] }),
      ).toBe(
        "field mcp_servers[0]: MCP server srv: MCP tls.insecure_skip_verify is unsupported on " +
          "Cloudflare Workers: fetch() exposes no hook to disable upstream certificate verification",
      );
    });
    test("the stdio transport never reaches the tls leg (as in Rust)", () => {
      expectAccepted({ mcp_servers: [mcpServer({ tls: { ca_cert_path: "/etc/ca.pem" } })] });
    });
  });
});

describe("validate_api_keys", () => {
  const cases: [string, Record<string, unknown>, string][] = [
    ["blank id", { api_keys: [apiKey({ id: " " })] }, "field api_keys[0].id: cannot be empty"],
    [
      "duplicate id",
      { api_keys: [apiKey(), apiKey()] },
      "field api_keys[1].id: duplicate api key id k1",
    ],
    [
      "no credential at all",
      { api_keys: [apiKey({ key_env: null })] },
      "field api_keys[0].key_env: key_env, key, or key_hash is required",
    ],
    [
      "an unsupported key hash format",
      { api_keys: [apiKey({ key_env: null, key_hash: "sha256:abc" })] },
      "field api_keys[0].key_hash: unsupported key hash format",
    ],
    [
      "a blank organization_id (#515)",
      { api_keys: [apiKey({ platform_operator: null, organization_id: "   " })] },
      "field api_keys[0].organization_id: cannot be blank; omit it for a platform-operator key " +
        "(and set platform_operator = true) or name the tenant it belongs to",
    ],
    [
      "platform_operator = true AND a tenant (#515)",
      { api_keys: [apiKey({ organization_id: "org-1" })] },
      "field api_keys[0].platform_operator: api key k1 sets platform_operator = true and " +
        "organization_id = org-1; a platform-operator key is unscoped by definition, so it must " +
        "not also claim a tenant",
    ],
    [
      "an allowed model that does not exist",
      { api_keys: [apiKey({ allowed_models: ["ghost"] })] },
      "field api_keys[0].allowed_models: api key k1 allows unknown model ghost",
    ],
    [
      "a denied provider that does not exist",
      { api_keys: [apiKey({ denied_providers: ["ghost"] })] },
      "field api_keys[0].denied_providers: api key k1 denies unknown provider ghost",
    ],
    [
      "an empty region_allowlist entry",
      { api_keys: [apiKey({ region_allowlist: [""] })] },
      "field api_keys[0].region_allowlist: cannot contain an empty value",
    ],
    [
      "a region no provider declares (#173)",
      {
        providers: [provider({ region: "us-east-1" })],
        api_keys: [apiKey({ region_allowlist: ["eu-west-1"] })],
      },
      "field api_keys[0].region_allowlist: api key k1 requires region eu-west-1 but no configured " +
        "provider declares it",
    ],
  ];
  test.each(cases)("rejects %s", (_name, raw, expected) => {
    expect(firstError(raw)).toBe(expected);
  });

  test("accepts a key scoped to a declared model, provider and region", () => {
    expectAccepted({
      providers: [provider({ region: "us-east-1" })],
      models: [model()],
      api_keys: [
        apiKey({
          platform_operator: null,
          organization_id: "org-1",
          allowed_models: ["gpt"],
          allowed_providers: ["openai"],
          region_allowlist: ["us-east-1"],
        }),
      ],
    });
  });

  test("MCP tools/servers are addressable policy targets (add_mcp_policy_targets)", () => {
    expectAccepted({
      mcp_servers: [mcpServer()],
      api_keys: [apiKey({ allowed_models: ["mcp_tool:srv-echo"], denied_providers: ["mcp:srv"] })],
    });
  });
});

describe("validate_policies + validate_gateway_configs", () => {
  const cases: [string, Record<string, unknown>, string][] = [
    [
      "a blank policy name",
      { policies: [{ name: " " }] },
      "field policies[0].name: cannot be empty",
    ],
    [
      "a duplicate policy name",
      { policies: [{ name: "p" }, { name: "p" }] },
      "field policies[1].name: duplicate policy name p",
    ],
    [
      "a non-deny effect",
      { policies: [{ name: "p", effect: "allow" }] },
      "field policies[0].effect: only deny is supported in the MVP",
    ],
    [
      "a policy naming an unknown api key",
      { policies: [{ name: "p", api_key_ids: ["ghost"] }] },
      "field policies[0].api_key_ids: policy p references unknown api key ghost",
    ],
    [
      "a policy naming an unknown model",
      { policies: [{ name: "p", models: ["ghost"] }] },
      "field policies[0].models: policy p references unknown model ghost",
    ],
    [
      "a gateway config with no cache_enabled decision",
      { gateway_configs: [{ id: "g", name: "g" }] },
      "field gateway_configs[0]: cache_enabled is required for this profile slice",
    ],
    [
      "a gateway config revision of zero",
      { gateway_configs: [{ id: "g", name: "g", revision: 0, cache_enabled: true }] },
      "field gateway_configs[0].revision: must be greater than zero",
    ],
    [
      "a gateway config naming an unknown api key",
      {
        gateway_configs: [{ id: "g", name: "g", cache_enabled: false, api_key_ids: ["ghost"] }],
      },
      "field gateway_configs[0].api_key_ids: gateway config g references unknown api key ghost",
    ],
  ];
  test.each(cases)("rejects %s", (_name, raw, expected) => {
    expect(firstError(raw)).toBe(expected);
  });

  test("accepts a policy + profile that name real entities", () => {
    expectAccepted({
      providers: [provider()],
      models: [model()],
      api_keys: [apiKey()],
      policies: [
        { name: "p", effect: "DENY", api_key_ids: ["k1"], models: ["gpt"], providers: ["openai"] },
      ],
      gateway_configs: [{ id: "g", name: "g", cache_enabled: true, api_key_ids: ["k1"] }],
    });
  });
});

describe("validate_agent_upstreams", () => {
  const upstream = (extra: Record<string, unknown> = {}) => ({
    id: "a1",
    name: "agent",
    endpoint: "https://agent.example/a2a",
    capabilities: ["invoke"],
    ...extra,
  });
  const cases: [string, Record<string, unknown>, string][] = [
    [
      "a duplicate id",
      { agent_upstreams: [upstream(), upstream()] },
      "field agent_upstreams[1].id: duplicate agent upstream id a1",
    ],
    [
      "a blank name",
      { agent_upstreams: [upstream({ name: "" })] },
      "field agent_upstreams[0].name: cannot be empty",
    ],
    [
      "a non-http endpoint",
      { agent_upstreams: [upstream({ endpoint: "grpc://agent" })] },
      "field agent_upstreams[0].endpoint: must start with http:// or https://",
    ],
    [
      "an empty tenant id",
      { agent_upstreams: [upstream({ tenant_ids: ["org-1", " "] })] },
      "field agent_upstreams[0].tenant_ids: cannot contain empty tenant ids",
    ],
    [
      "no declared capability",
      { agent_upstreams: [upstream({ capabilities: [] })] },
      "field agent_upstreams[0].capabilities: at least one capability is required",
    ],
  ];
  test.each(cases)("rejects %s", (_name, raw, expected) => {
    expect(firstError(raw)).toBe(expected);
  });

  test("accepts a streaming A2A upstream", () => {
    expectAccepted({ agent_upstreams: [upstream({ capabilities: ["invoke", "stream"] })] });
  });
});

describe("validate_upstreams + validate_routes", () => {
  const upstream = (extra: Record<string, unknown> = {}) => ({
    name: "app",
    url: "http://127.0.0.1:9000",
    ...extra,
  });
  const route = (extra: Record<string, unknown> = {}) => ({ name: "r", upstream: "app", ...extra });
  const withUpstream = (routes: Record<string, unknown>[]) => ({
    upstreams: [upstream()],
    routes,
  });
  const cases: [string, Record<string, unknown>, string][] = [
    [
      "an upstream with neither url nor urls",
      { upstreams: [{ name: "app" }] },
      "field upstreams[0].url: upstream must define url or urls",
    ],
    [
      "a duplicate upstream name",
      { upstreams: [upstream(), upstream()] },
      "field upstreams[1].name: duplicate upstream name app",
    ],
    [
      "an upstream endpoint with a non-http scheme",
      { upstreams: [upstream({ url: "ftp://files.example" })] },
      "field upstreams[0].urls[0]: upstream app has invalid endpoint ftp://files.example: " +
        "upstream URL scheme must be http or https",
    ],
    [
      "a route on an unknown upstream",
      { routes: [route({ upstream: "ghost" })] },
      "field routes[0].upstream: route r references unknown upstream ghost",
    ],
    [
      "a path prefix without a leading slash",
      withUpstream([route({ path_prefixes: ["v1"] })]),
      "field routes[0].path_prefixes: path prefix must start with /",
    ],
    [
      "a strip_prefix without a leading slash (reported on path_prefixes, as in Rust)",
      withUpstream([route({ strip_prefix: "v1" })]),
      "field routes[0].path_prefixes: path prefix must start with /",
    ],
    [
      "an add_prefix without a leading slash",
      withUpstream([route({ add_prefix: "v1" })]),
      "field routes[0].add_prefix: add_prefix must start with /",
    ],
    [
      "an invalid request header name",
      withUpstream([route({ request_headers: [{ name: "x forwarded", value: "1" }] })]),
      "field routes[0].request_headers[0].name: invalid header name",
    ],
    [
      "a header value carrying a newline (response splitting)",
      withUpstream([
        route({ response_headers: [{ name: "x-trace", value: "a\r\nSet-Cookie: b" }] }),
      ]),
      "field routes[0].response_headers[0].value: invalid header value",
    ],
    [
      "an invalid match-header name",
      withUpstream([route({ match_headers: [{ name: "bad:name", value: "1" }] })]),
      "field routes[0].match_headers[0].name: invalid header name",
    ],
  ];
  test.each(cases)("rejects %s", (_name, raw, expected) => {
    expect(firstError(raw)).toBe(expected);
  });

  test("accepts a well-formed upstream + route pair", () => {
    expectAccepted(
      withUpstream([
        route({
          path_prefixes: ["/v1"],
          strip_prefix: "/v1",
          add_prefix: "/api",
          match_headers: [{ name: "x-tenant", value: "acme" }],
          request_headers: [{ name: "x-forwarded-by", value: "ferrogate" }],
          response_headers: [{ name: "x-cache", value: "" }],
        }),
      ]),
    );
  });
});
