/**
 * Port of `ferrogate-config`'s `caddyfile/parser.rs` + the `Parser`-method
 * helpers of `parser_support.rs`: the recursive-descent parser over the
 * Caddyfile compatibility subset, producing a `GatewayConfig` or throwing a
 * `CaddyfileDiagnostic` (inventory §5.6).
 *
 * PORT-TODO(L: inventory §5.8) — PLATFORM LIMIT (API SHAPE), NOT CLOSED.
 *
 * The grammar itself is ported 1:1: every directive the Rust parser matches has
 * a case here, and a migrating operator's `Caddyfile` compiles to the same
 * intermediate model with the same `CaddyfileDiagnostic` on failure.
 *
 * The ONE divergence is the same platform limit as `../secrets.ts`: the Rust
 * parser resolved an `organization_id` env reference through `std::env::var`,
 * which workerd does not have (a Worker's environment is the per-invocation
 * `env` object, not ambient process state). CLOSEST BEHAVIOR IMPLEMENTED:
 * `parseCaddyfile(raw, file, env?)` takes the environment as an explicit
 * argument that the caller threads down from the Worker `env` binding.
 *
 * NOTE (not a port gap): the Caddyfile bridge is a legacy migration path. It is
 * kept at parity so migration works, but a CF-native deployment configures via
 * wrangler vars / KV / D1 and never enters this module.
 */
import { CaddyfileDiagnostic } from "../diagnostic.js";
import { type ModelCapability, modelCapabilitySchema } from "../schema/enums.js";
import type { EnvSource } from "../secrets.js";

/** `ModelCapability::from_str`'s accept set, in the Rust match-arm order. */
const MODEL_CAPABILITIES: readonly ModelCapability[] = modelCapabilitySchema.options;
import { type Token, lex } from "./lexer.js";
import {
  adaptSiteAddress,
  caddyPathToPrefix,
  envReference,
  globalSuggestion,
  looksLikeUpstream,
  modelRefArg,
} from "./parser-support.js";
import {
  type GatewayApiKey,
  type GatewayConfig,
  type GatewayModel,
  type GatewayProvider,
  type GatewayTlsAcmeConfig,
  defaultGatewayConfig,
  defaultGatewayRoute,
} from "./types.js";

/** Parse a Caddyfile source into the intermediate `GatewayConfig`. Throws `CaddyfileDiagnostic`. */
export function parseCaddyfile(raw: string, file: string, env?: EnvSource): GatewayConfig {
  return new Parser(raw, file, env).parse();
}

function emptyAcme(host: string | null): GatewayTlsAcmeConfig {
  return {
    domains: host !== null ? [host] : [],
    email: null,
    directory_url: null,
    challenge: null,
    http_challenge_listen: null,
    storage_dir: null,
    dns_provider: null,
    dns_config: {},
    dns_hook_set: null,
    dns_hook_cleanup: null,
    renewal_window_secs: null,
    renewal_check_interval_secs: null,
    renewal_retry_interval_secs: null,
    auto_graceful_reload: null,
  };
}

class Parser {
  private readonly file: string;
  private readonly tokens: Token[];
  private readonly env: EnvSource;
  private pos = 0;
  private readonly config: GatewayConfig;
  private upstreamCount = 0;
  private routeCount = 0;

  constructor(raw: string, file: string, env?: EnvSource) {
    this.file = file;
    this.tokens = lex(raw);
    this.env = env ?? (globalThis as { process?: { env?: EnvSource } }).process?.env ?? {};
    this.config = { ...defaultGatewayConfig(), listen: "127.0.0.1:8080" };
  }

  parse(): GatewayConfig {
    this.skipNewlines();
    while (!this.isEof()) {
      if (this.consumeLbrace()) {
        this.parseGlobalOptions();
      } else {
        this.parseSiteBlock();
      }
      this.skipNewlines();
    }
    return this.config;
  }

  // --- diagnostics -----------------------------------------------------------

  private unsupported(token: Token, directive: string, suggestion: string): CaddyfileDiagnostic {
    return new CaddyfileDiagnostic({
      file: this.file,
      line: token.line,
      column: token.column,
      message: `unsupported directive \`${directive}\`: not part of the FerroGate Caddyfile MVP subset`,
      directive,
      suggestion,
    });
  }

  private invalidArgument(
    token: Token,
    directive: string,
    suggestion: string,
  ): CaddyfileDiagnostic {
    return new CaddyfileDiagnostic({
      file: this.file,
      line: token.line,
      column: token.column,
      message: `invalid argument for \`${directive}\`: the directive is supported, its argument is not`,
      directive,
      suggestion,
    });
  }

  private expected(what: string): CaddyfileDiagnostic {
    const token = this.tokens[this.pos] ?? { kind: { type: "newline" }, line: 1, column: 1 };
    return new CaddyfileDiagnostic({
      file: this.file,
      line: token.line,
      column: token.column,
      directive: what,
      message: `unexpected Caddyfile syntax: expected \`${what}\``,
      suggestion: "check braces and directive line breaks",
    });
  }

  // --- token helpers ---------------------------------------------------------

  private consumeWordWithToken(): { word: string; token: Token } | null {
    this.skipNewlines();
    const token = this.tokens[this.pos];
    if (token !== undefined && token.kind.type === "word") {
      this.pos += 1;
      return { word: token.kind.value, token };
    }
    return null;
  }

  private consumeLineArgs(): string[] {
    return this.consumeLineArgsUntil();
  }

  private consumeLineArgsUntilBlock(): string[] {
    return this.consumeLineArgsUntil();
  }

  private consumeLineArgsUntil(): string[] {
    const args: string[] = [];
    for (;;) {
      const token = this.tokens[this.pos];
      if (token === undefined) break;
      if (token.kind.type === "word") {
        args.push(token.kind.value);
        this.pos += 1;
      } else if (token.kind.type === "lbrace") {
        break;
      } else {
        // rbrace or newline
        if (token.kind.type === "newline") this.pos += 1;
        break;
      }
    }
    return args;
  }

  private consumeLbraceAfterLineArgs(): boolean {
    for (;;) {
      const token = this.tokens[this.pos];
      if (token === undefined) break;
      if (token.kind.type === "lbrace") {
        this.pos += 1;
        return true;
      }
      this.pos += 1;
    }
    return false;
  }

  private consumeOptionalEmptyBlock(): void {
    if (!this.consumeLbrace()) return;
    let depth = 1;
    while (this.pos < this.tokens.length) {
      const token = this.tokens[this.pos]!;
      if (token.kind.type === "lbrace") depth += 1;
      else if (token.kind.type === "rbrace") {
        depth -= 1;
        if (depth === 0) {
          this.pos += 1;
          return;
        }
      }
      this.pos += 1;
    }
    throw this.expected("closing brace");
  }

  private consumeLbrace(): boolean {
    this.skipNewlines();
    const token = this.tokens[this.pos];
    if (token !== undefined && token.kind.type === "lbrace") {
      this.pos += 1;
      return true;
    }
    return false;
  }

  private consumeRbrace(): boolean {
    this.skipNewlines();
    const token = this.tokens[this.pos];
    if (token !== undefined && token.kind.type === "rbrace") {
      this.pos += 1;
      return true;
    }
    return false;
  }

  private skipNewlines(): void {
    while (this.tokens[this.pos]?.kind.type === "newline") this.pos += 1;
  }

  private isEof(): boolean {
    return this.pos >= this.tokens.length;
  }

  private addStaticResponse(
    host: string | null,
    inheritedPrefix: string | null,
    args: string[],
  ): void {
    this.routeCount += 1;
    const pathArg = args.find((arg) => arg.startsWith("/"));
    const path =
      pathArg !== undefined
        ? caddyPathToPrefix(pathArg)
        : inheritedPrefix !== null
          ? inheritedPrefix
          : "/";
    const body = args.find((arg) => !arg.startsWith("/") && !/^\d+$/.test(arg)) ?? "";
    let status = 200;
    for (let i = args.length - 1; i >= 0; i -= 1) {
      const arg = args[i]!;
      if (/^\d+$/.test(arg)) {
        status = Number.parseInt(arg, 10);
        break;
      }
    }
    this.config.routes.push({
      ...defaultGatewayRoute(),
      name: `caddyfile-respond-${this.routeCount}`,
      hosts: host !== null ? [host] : [],
      path_prefixes: [path],
      static_response: { body, status },
    });
  }

  // --- grammar ---------------------------------------------------------------

  private parseGlobalOptions(): void {
    for (;;) {
      this.skipNewlines();
      if (this.consumeRbrace()) return;
      const consumed = this.consumeWordWithToken();
      if (consumed === null) {
        this.pos += 1;
        return;
      }
      const { word: directive, token } = consumed;
      const args = this.consumeLineArgs();
      switch (directive) {
        case "admin":
          if (args[0] !== undefined) this.config.admin = args[0];
          break;
        case "auth":
          if (args[0] === "off") this.config.auth_disabled = true;
          else if (args[0] === "on") this.config.auth_disabled = false;
          else
            throw this.unsupported(
              token,
              directive,
              "expected `auth off` (this gateway requires no credential -- every request is admitted as an unrestricted platform operator) or `auth on` (the default: every request must present a credential)",
            );
          break;
        case "debug":
        case "log":
          break;
        default:
          throw this.unsupported(token, directive, globalSuggestion(args));
      }
    }
  }

  private parseSiteBlock(): void {
    const consumed = this.consumeWordWithToken();
    if (consumed === null) throw this.expected("site address");
    const { word: address, token } = consumed;
    if (!this.consumeLbraceAfterLineArgs()) {
      throw this.unsupported(
        token,
        address,
        "expected a Caddyfile site block like `:8080 { ... }`",
      );
    }
    const { listen, host } = adaptSiteAddress(address);
    if (listen !== null) this.config.listen = listen;

    for (;;) {
      this.skipNewlines();
      if (this.consumeRbrace()) return;
      this.parseSiteDirective(host, null, false);
    }
  }

  private parseSiteDirective(
    host: string | null,
    inheritedPrefix: string | null,
    inheritedStrip: boolean,
  ): void {
    const consumed = this.consumeWordWithToken();
    if (consumed === null) return;
    const { word: directive, token } = consumed;
    const args = this.consumeLineArgsUntilBlock();
    switch (directive) {
      case "log":
        this.config.logs.push({ route: null });
        this.consumeOptionalEmptyBlock();
        return;
      case "route":
      case "handle":
      case "handle_path": {
        const firstArg = args[0];
        const prefix = firstArg?.startsWith("/") ? caddyPathToPrefix(firstArg) : null;
        const strip = prefix !== null ? directive === "handle_path" : inheritedStrip;
        if (!this.consumeLbrace()) return;
        for (;;) {
          this.skipNewlines();
          if (this.consumeRbrace()) return;
          this.parseSiteDirective(host, prefix ?? inheritedPrefix, strip);
        }
      }
      case "reverse_proxy":
        this.parseReverseProxy(host, inheritedPrefix, inheritedStrip, args);
        return;
      case "ai_gateway":
        this.parseAiGateway(token);
        return;
      case "respond":
        this.addStaticResponse(host, inheritedPrefix, args);
        return;
      case "tls":
        if (args.length >= 2) {
          this.config.tls = {
            cert_path: args[0] as NonNullable<(typeof args)[0]>,
            key_path: args[1] as NonNullable<(typeof args)[1]>,
          };
          this.consumeOptionalEmptyBlock();
        } else if (this.consumeLbrace()) {
          this.parseTlsBlock(host);
        } else {
          this.config.tls_acme = emptyAcme(host);
        }
        return;
      case "header":
      case "rewrite":
      case "uri":
      case "redir":
      case "encode":
        this.consumeOptionalEmptyBlock();
        return;
      default:
        if (directive.startsWith("@")) {
          if (
            args[0] !== undefined &&
            ["path", "host", "method", "header", "query"].includes(args[0])
          ) {
            return;
          }
          this.consumeOptionalEmptyBlock();
          return;
        }
        throw this.unsupported(
          token,
          directive,
          "supported MVP directives are site blocks, matchers, reverse_proxy, ai_gateway, route, handle, handle_path, header, rewrite, uri, respond, redir, encode, tls, and log",
        );
    }
  }

  private parseTlsBlock(host: string | null): void {
    const acme = emptyAcme(host);
    for (;;) {
      this.skipNewlines();
      if (this.consumeRbrace()) {
        this.config.tls_acme = acme;
        return;
      }
      const consumed = this.consumeWordWithToken();
      if (consumed === null) {
        this.pos += 1;
        this.config.tls_acme = acme;
        return;
      }
      const { word: directive, token } = consumed;
      const args = this.consumeLineArgsUntilBlock();
      switch (directive) {
        case "domain":
        case "domains":
          acme.domains.push(...args);
          break;
        case "email":
          acme.email = args[0] ?? null;
          break;
        case "ca":
        case "dir":
        case "directory_url":
          acme.directory_url = args[0] ?? null;
          break;
        case "challenge":
          acme.challenge = args[0] ?? null;
          break;
        case "http_challenge_listen":
          acme.http_challenge_listen = args[0] ?? null;
          break;
        case "storage":
          acme.storage_dir = args[0] ?? null;
          break;
        case "dns":
          if (args[0] === "exec" && args.length >= 3) {
            acme.dns_hook_set = args[1] as NonNullable<(typeof args)[1]>;
            acme.dns_hook_cleanup = args[2] as NonNullable<(typeof args)[2]>;
          } else if (args[0] !== undefined) {
            acme.dns_provider = args[0];
          }
          this.parseTlsDnsConfigBlock(acme);
          break;
        case "dns_hook_set":
          acme.dns_hook_set = args[0] ?? null;
          break;
        case "dns_hook_cleanup":
          acme.dns_hook_cleanup = args[0] ?? null;
          break;
        case "renewal_window_secs":
          acme.renewal_window_secs = parseFirstU64(args);
          break;
        case "renewal_check_interval_secs":
          acme.renewal_check_interval_secs = parseFirstU64(args);
          break;
        case "renewal_retry_interval_secs":
          acme.renewal_retry_interval_secs = parseFirstU64(args);
          break;
        case "auto_graceful_reload":
          acme.auto_graceful_reload = parseBool(args[0]);
          break;
        // biome-ignore lint/suspicious/noFallthroughSwitchClause: intentional — an `issuer` directive that is not `issuer acme` deliberately falls through to the default handling below
        case "issuer":
          if (args[0] === "acme") {
            this.parseTlsIssuerAcmeBlock(acme);
            break;
          }
        // falls through to default when not `issuer acme`
        // eslint-disable-next-line no-fallthrough
        default:
          throw this.unsupported(
            token,
            directive,
            "inside tls blocks, FerroGate supports domain(s), email, ca/dir, storage, dns <provider> { ... }, dns exec <set-hook> <cleanup-hook> { ... }, dns_hook_set, dns_hook_cleanup, renewal settings, and issuer acme",
          );
      }
    }
  }

  private parseTlsDnsConfigBlock(acme: GatewayTlsAcmeConfig): void {
    if (!this.consumeLbrace()) return;
    for (;;) {
      this.skipNewlines();
      if (this.consumeRbrace()) return;
      const consumed = this.consumeWordWithToken();
      if (consumed === null) {
        this.pos += 1;
        return;
      }
      const { word: directive } = consumed;
      const args = this.consumeLineArgs();
      if (directive === "provider") acme.dns_provider = args[0] ?? null;
      else if (args[0] !== undefined) acme.dns_config[directive] = args[0];
    }
  }

  private parseTlsIssuerAcmeBlock(acme: GatewayTlsAcmeConfig): void {
    if (!this.consumeLbrace()) return;
    for (;;) {
      this.skipNewlines();
      if (this.consumeRbrace()) return;
      const consumed = this.consumeWordWithToken();
      if (consumed === null) {
        this.pos += 1;
        return;
      }
      const { word: directive, token } = consumed;
      const args = this.consumeLineArgs();
      switch (directive) {
        case "email":
          acme.email = args[0] ?? null;
          break;
        case "ca":
        case "dir":
        case "directory_url":
          acme.directory_url = args[0] ?? null;
          break;
        case "renewal_window_secs":
          acme.renewal_window_secs = parseFirstU64(args);
          break;
        case "renewal_check_interval_secs":
          acme.renewal_check_interval_secs = parseFirstU64(args);
          break;
        case "renewal_retry_interval_secs":
          acme.renewal_retry_interval_secs = parseFirstU64(args);
          break;
        case "auto_graceful_reload":
          acme.auto_graceful_reload = parseBool(args[0]);
          break;
        default:
          throw this.unsupported(
            token,
            directive,
            "inside tls issuer acme, FerroGate supports email, ca/dir, and renewal settings",
          );
      }
    }
  }

  private parseAiGateway(token: Token): void {
    if (!this.consumeLbrace()) {
      throw this.unsupported(
        token,
        "ai_gateway",
        "expected `ai_gateway { provider ... model ... api_key ... }`",
      );
    }
    for (;;) {
      this.skipNewlines();
      if (this.consumeRbrace()) return;
      const consumed = this.consumeWordWithToken();
      if (consumed === null) {
        this.pos += 1;
        return;
      }
      const { word: directive, token: dirToken } = consumed;
      const args = this.consumeLineArgsUntilBlock();
      switch (directive) {
        case "provider":
          this.parseAiProvider(dirToken, args);
          break;
        case "model":
          this.parseAiModel(dirToken, args);
          break;
        case "api_key":
          this.parseAiApiKey(dirToken, args);
          break;
        case "route":
        case "policy":
          this.consumeOptionalEmptyBlock();
          break;
        default:
          throw this.unsupported(
            dirToken,
            directive,
            "inside ai_gateway, FerroGate supports provider, model, api_key, route and policy placeholders",
          );
      }
    }
  }

  private parseAiProvider(token: Token, args: string[]): void {
    const name = args[0];
    if (name === undefined) throw this.expected("provider name");
    const provider: GatewayProvider = {
      name,
      kind: "openai",
      base_url: "",
      api_key_env: null,
      openrouter_http_referer: null,
      openrouter_x_title: null,
    };
    if (!this.consumeLbrace()) {
      throw this.unsupported(
        token,
        "provider",
        "expected `provider <name> { base_url <url> api_key {env.NAME} }`",
      );
    }
    for (;;) {
      this.skipNewlines();
      if (this.consumeRbrace()) break;
      const consumed = this.consumeWordWithToken();
      if (consumed === null) {
        this.pos += 1;
        break;
      }
      const { word: directive, token: dirToken } = consumed;
      const inner = this.consumeLineArgs();
      switch (directive) {
        case "kind":
          if (inner[0] !== undefined) provider.kind = inner[0];
          break;
        case "base_url":
          if (inner[0] !== undefined) provider.base_url = inner[0];
          break;
        case "api_key":
          if (inner[0] !== undefined) provider.api_key_env = envReference(inner[0]);
          break;
        case "openrouter_http_referer":
          provider.openrouter_http_referer = inner[0] ?? null;
          break;
        case "openrouter_x_title":
          provider.openrouter_x_title = inner.join(" ");
          break;
        default:
          throw this.unsupported(
            dirToken,
            directive,
            "inside provider blocks, FerroGate supports kind, base_url, api_key env.NAME/{env.NAME}, openrouter_http_referer and openrouter_x_title",
          );
      }
    }
    this.config.providers.push(provider);
  }

  private parseAiModel(token: Token, args: string[]): void {
    const name = args[0];
    if (name === undefined) throw this.expected("model name");
    const ref = modelRefArg(args);
    if (ref === null) {
      throw this.unsupported(
        token,
        "model",
        "expected `model <name> -> <provider>:<provider_model>`",
      );
    }
    const colon = ref.indexOf(":");
    if (colon === -1) {
      throw this.unsupported(token, "model", "model target must use `<provider>:<provider_model>`");
    }
    const model: GatewayModel = {
      name,
      provider: ref.slice(0, colon),
      provider_model: ref.slice(colon + 1),
      capabilities: [],
      context_window: null,
      input_price_per_1m: null,
      output_price_per_1m: null,
    };
    if (this.consumeLbrace()) {
      for (;;) {
        this.skipNewlines();
        if (this.consumeRbrace()) break;
        const consumed = this.consumeWordWithToken();
        if (consumed === null) {
          this.pos += 1;
          break;
        }
        const { word: directive, token: dirToken } = consumed;
        const inner = this.consumeLineArgs();
        switch (directive) {
          case "capabilities":
            // Rust: `value.parse::<ModelCapability>()`, whose `FromStr::Err` is
            // fed to `self.unsupported(&token, directive, reason)` — so an
            // unknown slug is a diagnostic whose `directive` is `capabilities`
            // and whose suggestion is the `FromStr` message.
            model.capabilities = inner.map((value) => {
              if (!MODEL_CAPABILITIES.includes(value as ModelCapability)) {
                throw this.unsupported(
                  dirToken,
                  directive,
                  `unknown model capability "${value}"; expected one of ${MODEL_CAPABILITIES.join(", ")}`,
                );
              }
              return value as ModelCapability;
            });
            break;
          case "context_window":
            model.context_window = inner[0] !== undefined ? intOrNull(inner[0]) : null;
            break;
          case "input_price_per_1m":
            model.input_price_per_1m = inner[0] ?? null;
            break;
          case "output_price_per_1m":
            model.output_price_per_1m = inner[0] ?? null;
            break;
          default:
            throw this.unsupported(
              dirToken,
              directive,
              "inside model blocks, FerroGate supports capabilities, context_window, input_price_per_1m and output_price_per_1m",
            );
        }
      }
    }
    this.config.models.push(model);
  }

  private parseAiApiKey(token: Token, args: string[]): void {
    const id = args[0];
    if (id === undefined) throw this.expected("api_key id");
    const apiKey: GatewayApiKey = {
      id,
      name: id,
      key_env: null,
      key: null,
      key_hash: null,
      scopes: [],
      allowed_models: [],
      denied_models: [],
      allowed_providers: [],
      denied_providers: [],
      monthly_token_budget: null,
      request_limit_per_minute: null,
      organization_id: null,
      platform_operator: null,
    };
    if (!this.consumeLbrace()) {
      throw this.unsupported(
        token,
        "api_key",
        "expected `api_key <id> { key {env.NAME} scopes ... }`",
      );
    }
    for (;;) {
      this.skipNewlines();
      if (this.consumeRbrace()) break;
      const consumed = this.consumeWordWithToken();
      if (consumed === null) {
        this.pos += 1;
        break;
      }
      const { word: directive, token: dirToken } = consumed;
      const inner = this.consumeLineArgs();
      switch (directive) {
        case "name":
          if (inner.length > 0) apiKey.name = inner.join(" ");
          break;
        case "key":
          if (inner[0] !== undefined) {
            const env = envReference(inner[0]);
            if (env !== null) apiKey.key_env = env;
            else if (inner[0].startsWith("blake2b:")) apiKey.key_hash = inner[0];
            else apiKey.key = inner[0];
          }
          break;
        case "key_env":
          apiKey.key_env = inner[0] ?? null;
          break;
        case "key_hash":
          apiKey.key_hash = inner[0] ?? null;
          break;
        case "scopes":
          apiKey.scopes = inner;
          break;
        case "allowed_models":
          apiKey.allowed_models = inner;
          break;
        case "denied_models":
          apiKey.denied_models = inner;
          break;
        case "allowed_providers":
          apiKey.allowed_providers = inner;
          break;
        case "denied_providers":
          apiKey.denied_providers = inner;
          break;
        case "monthly_token_budget":
          apiKey.monthly_token_budget = inner[0] !== undefined ? intOrNull(inner[0]) : null;
          break;
        case "request_limit_per_minute":
          apiKey.request_limit_per_minute = inner[0] !== undefined ? intOrNull(inner[0]) : null;
          break;
        case "organization_id": {
          const value = inner[0];
          if (value !== undefined && value.trim().length > 0) {
            const envName = envReference(value);
            let resolved: string;
            if (envName !== null) {
              const fromEnv = this.env[envName];
              if (fromEnv === undefined) {
                throw this.invalidArgument(
                  dirToken,
                  directive,
                  `environment variable \`${envName}\` is not set; set it to a tenants.id or write the tenant id literally`,
                );
              }
              if (fromEnv.trim().length === 0) {
                throw this.invalidArgument(
                  dirToken,
                  directive,
                  `environment variable \`${envName}\` resolved to an empty tenant id; set it to a tenants.id`,
                );
              }
              resolved = fromEnv;
            } else {
              resolved = value;
            }
            apiKey.organization_id = resolved;
          } else {
            throw this.invalidArgument(
              dirToken,
              directive,
              "expected `organization_id <tenants.id>` (this key belongs to that one tenant); to give a key unrestricted cross-tenant access use `platform_operator on` instead",
            );
          }
          break;
        }
        case "platform_operator":
          if (inner[0] === "on" || inner[0] === "true") apiKey.platform_operator = true;
          else if (inner[0] === "off" || inner[0] === "false") apiKey.platform_operator = false;
          else
            throw this.invalidArgument(
              dirToken,
              directive,
              "expected `platform_operator on` (this key administers EVERY tenant) or `platform_operator off` (it does not); to scope a key to one tenant use `organization_id <tenants.id>` instead",
            );
          break;
        default:
          throw this.unsupported(
            dirToken,
            directive,
            "inside api_key blocks, FerroGate supports name, key, key_env, key_hash, scopes, allowed_models, denied_models, allowed_providers, denied_providers, monthly_token_budget, request_limit_per_minute, organization_id and platform_operator",
          );
      }
    }
    this.config.api_keys.push(apiKey);
  }

  private parseReverseProxy(
    host: string | null,
    inheritedPrefix: string | null,
    inheritedStrip: boolean,
    args: string[],
  ): void {
    const upstreamUrls = args.filter(looksLikeUpstream);
    const upstreamUrl = upstreamUrls[0];
    if (upstreamUrl === undefined) return;
    this.upstreamCount += 1;
    const upstreamName = `caddyfile-upstream-${this.upstreamCount}`;
    this.config.upstreams.push({
      name: upstreamName,
      url: upstreamUrl,
      urls: upstreamUrls.slice(1),
    });

    const requestHeaders: { name: string; value: string }[] = [];
    const responseHeaders: { name: string; value: string }[] = [];
    if (this.consumeLbrace()) {
      for (;;) {
        this.skipNewlines();
        if (this.consumeRbrace()) break;
        const consumed = this.consumeWordWithToken();
        if (consumed === null) break;
        const { word: directive, token: dirToken } = consumed;
        const inner = this.consumeLineArgs();
        switch (directive) {
          case "header_up":
            if (inner.length >= 2)
              requestHeaders.push({
                name: inner[0] as NonNullable<(typeof inner)[0]>,
                value: inner.slice(1).join(" "),
              });
            break;
          case "header_down":
            if (inner.length >= 2)
              responseHeaders.push({
                name: inner[0] as NonNullable<(typeof inner)[0]>,
                value: inner.slice(1).join(" "),
              });
            break;
          case "lb_policy":
          case "health_uri":
          case "health_interval":
          case "transport":
            break;
          default:
            throw this.unsupported(
              dirToken,
              directive,
              "inside reverse_proxy blocks, FerroGate MVP supports header_up plus basic load-balancing and health-check declarations as typed config placeholders",
            );
        }
      }
    }

    this.routeCount += 1;
    const prefix = inheritedPrefix ?? "/";
    this.config.routes.push({
      ...defaultGatewayRoute(),
      name: `caddyfile-route-${this.routeCount}`,
      upstream: upstreamName,
      hosts: host !== null ? [host] : [],
      path_prefixes: [prefix],
      strip_prefix: inheritedStrip ? prefix : null,
      request_headers: requestHeaders,
      response_headers: responseHeaders,
    });
  }
}

function parseFirstU64(args: string[]): number | null {
  return args[0] !== undefined ? intOrNull(args[0]) : null;
}

function intOrNull(value: string): number | null {
  return /^\d+$/.test(value) ? Number.parseInt(value, 10) : null;
}

function parseBool(value: string | undefined): boolean | null {
  if (value === "true") return true;
  if (value === "false") return false;
  return null;
}
