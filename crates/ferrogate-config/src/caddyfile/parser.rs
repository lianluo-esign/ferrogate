// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use crate::{
    CaddyfileDiagnostic, GatewayApiKey, GatewayConfig, GatewayHeader, GatewayLog, GatewayModel,
    GatewayProvider, GatewayRoute, GatewayTlsAcmeConfig, GatewayTlsConfig, GatewayUpstream,
};

use super::lexer::{lex, Token};
use super::parser_support::{
    adapt_site_address, caddy_path_to_prefix, env_reference, global_suggestion,
    looks_like_upstream, model_ref_arg,
};

pub fn parse_caddyfile(
    raw: &str,
    file: &str,
) -> std::result::Result<GatewayConfig, CaddyfileDiagnostic> {
    Parser::new(raw, file).parse()
}

pub(super) struct Parser<'a> {
    pub(super) file: &'a str,
    pub(super) tokens: Vec<Token>,
    pub(super) pos: usize,
    pub(super) config: GatewayConfig,
    pub(super) upstream_count: usize,
    pub(super) route_count: usize,
}

impl<'a> Parser<'a> {
    fn new(raw: &str, file: &'a str) -> Self {
        Self {
            file,
            tokens: lex(raw),
            pos: 0,
            config: GatewayConfig {
                listen: "127.0.0.1:8080".to_string(),
                ..GatewayConfig::default()
            },
            upstream_count: 0,
            route_count: 0,
        }
    }

    fn parse(mut self) -> std::result::Result<GatewayConfig, CaddyfileDiagnostic> {
        self.skip_newlines();
        while !self.is_eof() {
            if self.consume_lbrace() {
                self.parse_global_options()?;
            } else {
                self.parse_site_block()?;
            }
            self.skip_newlines();
        }
        Ok(self.config)
    }

    fn parse_global_options(&mut self) -> std::result::Result<(), CaddyfileDiagnostic> {
        loop {
            self.skip_newlines();
            if self.consume_rbrace() {
                return Ok(());
            }
            let Some((directive, token)) = self.consume_word_with_token() else {
                self.pos += 1;
                return Ok(());
            };
            let args = self.consume_line_args();
            match directive.as_str() {
                "admin" => {
                    if let Some(address) = args.first() {
                        self.config.admin = Some(address.clone());
                    }
                }
                // #542 rework: the authentication posture, spelled the Caddy way
                // (`admin off` is the model). Without this a Caddyfile-bridged
                // reverse proxy with no `ai_gateway { api_key ... }` block could
                // not express the open posture at all, and the startup gate's
                // refusal pointed it at a `[auth]` TOML section its config
                // format cannot contain. `auth off` is the only way a bridged
                // config runs without a credential source; omitting the
                // directive still means authentication is required.
                "auth" => {
                    match args.first().map(String::as_str) {
                        Some("off") => self.config.auth_disabled = true,
                        Some("on") => self.config.auth_disabled = false,
                        _ => return Err(self.unsupported(
                            &token,
                            directive,
                            "expected `auth off` (this gateway requires no credential -- every \
                             request is admitted as an unrestricted platform operator) or \
                             `auth on` (the default: every request must present a credential)"
                                .to_string(),
                        )),
                    }
                }
                "debug" | "log" => {}
                _ => return Err(self.unsupported(&token, directive, global_suggestion(&args))),
            }
        }
    }

    fn parse_site_block(&mut self) -> std::result::Result<(), CaddyfileDiagnostic> {
        let (address, token) = self
            .consume_word_with_token()
            .ok_or_else(|| self.expected("site address"))?;
        if !self.consume_lbrace_after_line_args() {
            return Err(self.unsupported(
                &token,
                address,
                "expected a Caddyfile site block like `:8080 { ... }`".to_string(),
            ));
        }

        let (listen, host) = adapt_site_address(&address);
        if let Some(listen) = listen {
            self.config.listen = listen;
        }

        loop {
            self.skip_newlines();
            if self.consume_rbrace() {
                return Ok(());
            }
            self.parse_site_directive(host.as_deref(), None, false)?;
        }
    }

    fn parse_site_directive(
        &mut self,
        host: Option<&str>,
        inherited_prefix: Option<&str>,
        inherited_strip: bool,
    ) -> std::result::Result<(), CaddyfileDiagnostic> {
        let Some((directive, token)) = self.consume_word_with_token() else {
            return Ok(());
        };
        let args = self.consume_line_args_until_block();
        match directive.as_str() {
            "log" => {
                self.config.logs.push(GatewayLog { route: None });
                self.consume_optional_empty_block()?;
                Ok(())
            }
            "route" | "handle" | "handle_path" => {
                let prefix = args
                    .first()
                    .filter(|arg| arg.starts_with('/'))
                    .map(|arg| caddy_path_to_prefix(arg));
                // `handle_path` strips its matched prefix before forwarding
                // upstream (matching real Caddy semantics); plain `route`/
                // `handle` forward the full original path. A block with no
                // path arg of its own (e.g. a bare matcher-only `route`)
                // inherits both the prefix and strip-ness from its parent.
                let strip = if prefix.is_some() {
                    directive == "handle_path"
                } else {
                    inherited_strip
                };
                if !self.consume_lbrace() {
                    return Ok(());
                }
                loop {
                    self.skip_newlines();
                    if self.consume_rbrace() {
                        return Ok(());
                    }
                    self.parse_site_directive(
                        host,
                        prefix.as_deref().or(inherited_prefix),
                        strip,
                    )?;
                }
            }
            "reverse_proxy" => {
                self.parse_reverse_proxy(host, inherited_prefix, inherited_strip, args)
            }
            "ai_gateway" => self.parse_ai_gateway(&token),
            "respond" => {
                self.add_static_response(host, inherited_prefix, args);
                Ok(())
            }
            "tls" => {
                if args.len() >= 2 {
                    self.config.tls = Some(GatewayTlsConfig {
                        cert_path: args[0].clone(),
                        key_path: args[1].clone(),
                    });
                    self.consume_optional_empty_block()?;
                } else if self.consume_lbrace() {
                    self.parse_tls_block(host)?;
                } else {
                    self.config.tls_acme = Some(GatewayTlsAcmeConfig {
                        domains: host.into_iter().map(ToString::to_string).collect(),
                        email: None,
                        directory_url: None,
                        challenge: None,
                        http_challenge_listen: None,
                        storage_dir: None,
                        dns_provider: None,
                        dns_config: Default::default(),
                        dns_hook_set: None,
                        dns_hook_cleanup: None,
                        renewal_window_secs: None,
                        renewal_check_interval_secs: None,
                        renewal_retry_interval_secs: None,
                        auto_graceful_reload: None,
                    });
                }
                Ok(())
            }
            "header" | "rewrite" | "uri" | "redir" | "encode" => {
                self.consume_optional_empty_block()?;
                Ok(())
            }
            directive if directive.starts_with('@') => {
                if args.first().is_some_and(|arg| {
                    matches!(arg.as_str(), "path" | "host" | "method" | "header" | "query")
                }) {
                    return Ok(());
                }
                self.consume_optional_empty_block()?;
                Ok(())
            }
            _ => Err(self.unsupported(
                &token,
                directive,
                "supported MVP directives are site blocks, matchers, reverse_proxy, ai_gateway, route, handle, handle_path, header, rewrite, uri, respond, redir, encode, tls, and log".to_string(),
            )),
        }
    }

    fn parse_tls_block(
        &mut self,
        host: Option<&str>,
    ) -> std::result::Result<(), CaddyfileDiagnostic> {
        let mut acme = GatewayTlsAcmeConfig {
            domains: host.into_iter().map(ToString::to_string).collect(),
            email: None,
            directory_url: None,
            challenge: None,
            http_challenge_listen: None,
            storage_dir: None,
            dns_provider: None,
            dns_config: Default::default(),
            dns_hook_set: None,
            dns_hook_cleanup: None,
            renewal_window_secs: None,
            renewal_check_interval_secs: None,
            renewal_retry_interval_secs: None,
            auto_graceful_reload: None,
        };

        loop {
            self.skip_newlines();
            if self.consume_rbrace() {
                self.config.tls_acme = Some(acme);
                return Ok(());
            }
            let Some((directive, token)) = self.consume_word_with_token() else {
                self.pos += 1;
                self.config.tls_acme = Some(acme);
                return Ok(());
            };
            let args = self.consume_line_args_until_block();
            match directive.as_str() {
                "domain" | "domains" => acme.domains.extend(args),
                "email" => acme.email = args.first().cloned(),
                "ca" | "dir" | "directory_url" => acme.directory_url = args.first().cloned(),
                "challenge" => acme.challenge = args.first().cloned(),
                "http_challenge_listen" => acme.http_challenge_listen = args.first().cloned(),
                "storage" => acme.storage_dir = args.first().cloned(),
                "dns" => {
                    if args.first().is_some_and(|value| value == "exec") && args.len() >= 3 {
                        acme.dns_hook_set = Some(args[1].clone());
                        acme.dns_hook_cleanup = Some(args[2].clone());
                    } else if let Some(provider) = args.first() {
                        acme.dns_provider = Some(provider.clone());
                    }
                    self.parse_tls_dns_config_block(&mut acme)?;
                }
                "dns_hook_set" => acme.dns_hook_set = args.first().cloned(),
                "dns_hook_cleanup" => acme.dns_hook_cleanup = args.first().cloned(),
                "renewal_window_secs" => acme.renewal_window_secs = parse_first_u64(&args),
                "renewal_check_interval_secs" => {
                    acme.renewal_check_interval_secs = parse_first_u64(&args);
                }
                "renewal_retry_interval_secs" => {
                    acme.renewal_retry_interval_secs = parse_first_u64(&args);
                }
                "auto_graceful_reload" => {
                    acme.auto_graceful_reload =
                        args.first().and_then(|value| value.parse::<bool>().ok());
                }
                "issuer" if args.first().is_some_and(|value| value == "acme") => {
                    self.parse_tls_issuer_acme_block(&mut acme)?;
                }
                _ => {
                    return Err(self.unsupported(
                        &token,
                        directive,
                        "inside tls blocks, FerroGate supports domain(s), email, ca/dir, storage, dns <provider> { ... }, dns exec <set-hook> <cleanup-hook> { ... }, dns_hook_set, dns_hook_cleanup, renewal settings, and issuer acme".to_string(),
                    ));
                }
            }
        }
    }

    fn parse_tls_dns_config_block(
        &mut self,
        acme: &mut GatewayTlsAcmeConfig,
    ) -> std::result::Result<(), CaddyfileDiagnostic> {
        if !self.consume_lbrace() {
            return Ok(());
        }
        loop {
            self.skip_newlines();
            if self.consume_rbrace() {
                return Ok(());
            }
            let Some((directive, _token)) = self.consume_word_with_token() else {
                self.pos += 1;
                return Ok(());
            };
            let args = self.consume_line_args();
            if directive == "provider" {
                acme.dns_provider = args.first().cloned();
            } else if let Some(value) = args.first() {
                acme.dns_config.insert(directive, value.clone());
            }
        }
    }

    fn parse_tls_issuer_acme_block(
        &mut self,
        acme: &mut GatewayTlsAcmeConfig,
    ) -> std::result::Result<(), CaddyfileDiagnostic> {
        if !self.consume_lbrace() {
            return Ok(());
        }
        loop {
            self.skip_newlines();
            if self.consume_rbrace() {
                return Ok(());
            }
            let Some((directive, token)) = self.consume_word_with_token() else {
                self.pos += 1;
                return Ok(());
            };
            let args = self.consume_line_args();
            match directive.as_str() {
                "email" => acme.email = args.first().cloned(),
                "ca" | "dir" | "directory_url" => acme.directory_url = args.first().cloned(),
                "renewal_window_secs" => acme.renewal_window_secs = parse_first_u64(&args),
                "renewal_check_interval_secs" => {
                    acme.renewal_check_interval_secs = parse_first_u64(&args);
                }
                "renewal_retry_interval_secs" => {
                    acme.renewal_retry_interval_secs = parse_first_u64(&args);
                }
                "auto_graceful_reload" => {
                    acme.auto_graceful_reload =
                        args.first().and_then(|value| value.parse::<bool>().ok());
                }
                _ => {
                    return Err(self.unsupported(
                        &token,
                        directive,
                        "inside tls issuer acme, FerroGate supports email, ca/dir, and renewal settings".to_string(),
                    ));
                }
            }
        }
    }

    fn parse_ai_gateway(&mut self, token: &Token) -> std::result::Result<(), CaddyfileDiagnostic> {
        if !self.consume_lbrace() {
            return Err(self.unsupported(
                token,
                "ai_gateway".to_string(),
                "expected `ai_gateway { provider ... model ... api_key ... }`".to_string(),
            ));
        }

        loop {
            self.skip_newlines();
            if self.consume_rbrace() {
                return Ok(());
            }
            let Some((directive, token)) = self.consume_word_with_token() else {
                self.pos += 1;
                return Ok(());
            };
            let args = self.consume_line_args_until_block();
            match directive.as_str() {
                "provider" => self.parse_ai_provider(&token, args)?,
                "model" => self.parse_ai_model(&token, args)?,
                "api_key" => self.parse_ai_api_key(&token, args)?,
                "route" | "policy" => {
                    self.consume_optional_empty_block()?;
                }
                _ => {
                    return Err(self.unsupported(
                        &token,
                        directive,
                        "inside ai_gateway, FerroGate supports provider, model, api_key, route and policy placeholders".to_string(),
                    ));
                }
            }
        }
    }

    fn parse_ai_provider(
        &mut self,
        token: &Token,
        args: Vec<String>,
    ) -> std::result::Result<(), CaddyfileDiagnostic> {
        let Some(name) = args.first().cloned() else {
            return Err(self.expected("provider name"));
        };
        let mut provider = GatewayProvider {
            name,
            kind: "openai".to_string(),
            base_url: String::new(),
            api_key_env: None,
            openrouter_http_referer: None,
            openrouter_x_title: None,
        };

        if !self.consume_lbrace() {
            return Err(self.unsupported(
                token,
                "provider".to_string(),
                "expected `provider <name> { base_url <url> api_key {env.NAME} }`".to_string(),
            ));
        }
        loop {
            self.skip_newlines();
            if self.consume_rbrace() {
                break;
            }
            let Some((directive, token)) = self.consume_word_with_token() else {
                self.pos += 1;
                break;
            };
            let args = self.consume_line_args();
            match directive.as_str() {
                "kind" => {
                    if let Some(kind) = args.first() {
                        provider.kind.clone_from(kind);
                    }
                }
                "base_url" => {
                    if let Some(base_url) = args.first() {
                        provider.base_url.clone_from(base_url);
                    }
                }
                "api_key" => {
                    if let Some(value) = args.first() {
                        provider.api_key_env = env_reference(value);
                    }
                }
                "openrouter_http_referer" => {
                    provider.openrouter_http_referer = args.first().cloned();
                }
                "openrouter_x_title" => {
                    provider.openrouter_x_title = Some(args.join(" "));
                }
                _ => {
                    return Err(self.unsupported(
                        &token,
                        directive,
                        "inside provider blocks, FerroGate supports kind, base_url, api_key env.NAME/{env.NAME}, openrouter_http_referer and openrouter_x_title".to_string(),
                    ));
                }
            }
        }

        self.config.providers.push(provider);
        Ok(())
    }

    fn parse_ai_model(
        &mut self,
        token: &Token,
        args: Vec<String>,
    ) -> std::result::Result<(), CaddyfileDiagnostic> {
        let Some(name) = args.first().cloned() else {
            return Err(self.expected("model name"));
        };
        let Some(provider_model_ref) = model_ref_arg(&args) else {
            return Err(self.unsupported(
                token,
                "model".to_string(),
                "expected `model <name> -> <provider>:<provider_model>`".to_string(),
            ));
        };
        let Some((provider, provider_model)) = provider_model_ref.split_once(':') else {
            return Err(self.unsupported(
                token,
                "model".to_string(),
                "model target must use `<provider>:<provider_model>`".to_string(),
            ));
        };
        let mut model = GatewayModel {
            name,
            provider: provider.to_string(),
            provider_model: provider_model.to_string(),
            capabilities: Vec::new(),
            context_window: None,
            input_price_per_1m: None,
            output_price_per_1m: None,
        };

        if self.consume_lbrace() {
            loop {
                self.skip_newlines();
                if self.consume_rbrace() {
                    break;
                }
                let Some((directive, token)) = self.consume_word_with_token() else {
                    self.pos += 1;
                    break;
                };
                let args = self.consume_line_args();
                match directive.as_str() {
                    "capabilities" => model.capabilities = args,
                    "context_window" => {
                        model.context_window = args.first().and_then(|value| value.parse().ok());
                    }
                    "input_price_per_1m" => model.input_price_per_1m = args.first().cloned(),
                    "output_price_per_1m" => model.output_price_per_1m = args.first().cloned(),
                    _ => {
                        return Err(self.unsupported(
                            &token,
                            directive,
                            "inside model blocks, FerroGate supports capabilities, context_window, input_price_per_1m and output_price_per_1m".to_string(),
                        ));
                    }
                }
            }
        }

        self.config.models.push(model);
        Ok(())
    }

    fn parse_ai_api_key(
        &mut self,
        token: &Token,
        args: Vec<String>,
    ) -> std::result::Result<(), CaddyfileDiagnostic> {
        let Some(id) = args.first().cloned() else {
            return Err(self.expected("api_key id"));
        };
        let mut api_key = GatewayApiKey {
            name: id.clone(),
            id,
            key_env: None,
            key: None,
            key_hash: None,
            scopes: Vec::new(),
            allowed_models: Vec::new(),
            denied_models: Vec::new(),
            allowed_providers: Vec::new(),
            denied_providers: Vec::new(),
            monthly_token_budget: None,
            request_limit_per_minute: None,
            organization_id: None,
            platform_operator: None,
        };

        if !self.consume_lbrace() {
            return Err(self.unsupported(
                token,
                "api_key".to_string(),
                "expected `api_key <id> { key {env.NAME} scopes ... }`".to_string(),
            ));
        }
        loop {
            self.skip_newlines();
            if self.consume_rbrace() {
                break;
            }
            let Some((directive, token)) = self.consume_word_with_token() else {
                self.pos += 1;
                break;
            };
            let args = self.consume_line_args();
            match directive.as_str() {
                "name" => {
                    if !args.is_empty() {
                        api_key.name = args.join(" ");
                    }
                }
                "key" => {
                    if let Some(value) = args.first() {
                        if let Some(env) = env_reference(value) {
                            api_key.key_env = Some(env);
                        } else if value.starts_with("blake2b:") {
                            api_key.key_hash = Some(value.clone());
                        } else {
                            api_key.key = Some(value.clone());
                        }
                    }
                }
                "key_env" => api_key.key_env = args.first().cloned(),
                "key_hash" => api_key.key_hash = args.first().cloned(),
                "scopes" => api_key.scopes = args,
                "allowed_models" => api_key.allowed_models = args,
                "denied_models" => api_key.denied_models = args,
                "allowed_providers" => api_key.allowed_providers = args,
                "denied_providers" => api_key.denied_providers = args,
                "monthly_token_budget" => {
                    api_key.monthly_token_budget =
                        args.first().and_then(|value| value.parse().ok());
                }
                "request_limit_per_minute" => {
                    api_key.request_limit_per_minute =
                        args.first().and_then(|value| value.parse().ok());
                }
                // #540: the tenancy vocabulary, spelled the Caddy way, for the
                // same reason `auth off` exists (#542). Once an undeclared key
                // is refused at load, a bridged config needs SOME way to
                // declare one -- and the refusal cannot honestly point a
                // Caddyfile at a `[[api_keys]]` TOML field its format has no
                // grammar for. Omitting both directives still means "this key
                // said nothing", which is exactly what gets refused.
                // #540 rework: a bare `organization_id` with no argument used to
                // be `args.first().cloned()` -> `None`, i.e. silently the same
                // as writing nothing -- while the `platform_operator` arm
                // beside it rejected a missing value with a span. It fails
                // closed either way, but "silently ignored" is the shape that
                // makes a typo look like a declaration, and this directive's
                // whole job is to be the declaration.
                "organization_id" => match args.first() {
                    Some(value) if !value.trim().is_empty() => {
                        api_key.organization_id = Some(value.clone());
                    }
                    _ => {
                        return Err(self.invalid_argument(
                            &token,
                            directive,
                            "expected `organization_id <tenants.id>` (this key belongs to that \
                             one tenant); to give a key unrestricted cross-tenant access use \
                             `platform_operator on` instead"
                                .to_string(),
                        ));
                    }
                },
                "platform_operator" => match args.first().map(String::as_str) {
                    Some("on" | "true") => api_key.platform_operator = Some(true),
                    Some("off" | "false") => api_key.platform_operator = Some(false),
                    _ => {
                        return Err(self.invalid_argument(
                            &token,
                            directive,
                            "expected `platform_operator on` (this key administers EVERY tenant) \
                             or `platform_operator off` (it does not); to scope a key to one \
                             tenant use `organization_id <tenants.id>` instead"
                                .to_string(),
                        ));
                    }
                },
                _ => {
                    return Err(self.unsupported(
                        &token,
                        directive,
                        "inside api_key blocks, FerroGate supports name, key, key_env, key_hash, scopes, allowed_models, denied_models, allowed_providers, denied_providers, monthly_token_budget, request_limit_per_minute, organization_id and platform_operator".to_string(),
                    ));
                }
            }
        }

        self.config.api_keys.push(api_key);
        Ok(())
    }

    fn parse_reverse_proxy(
        &mut self,
        host: Option<&str>,
        inherited_prefix: Option<&str>,
        inherited_strip: bool,
        args: Vec<String>,
    ) -> std::result::Result<(), CaddyfileDiagnostic> {
        let upstream_urls = args
            .iter()
            .filter(|arg| looks_like_upstream(arg))
            .cloned()
            .collect::<Vec<_>>();
        let Some(upstream_url) = upstream_urls.first().cloned() else {
            return Ok(());
        };
        self.upstream_count += 1;
        let upstream_name = format!("caddyfile-upstream-{}", self.upstream_count);
        self.config.upstreams.push(GatewayUpstream {
            name: upstream_name.clone(),
            url: upstream_url,
            urls: upstream_urls.into_iter().skip(1).collect(),
        });

        let mut request_headers = Vec::new();
        let mut response_headers = Vec::new();
        if self.consume_lbrace() {
            loop {
                self.skip_newlines();
                if self.consume_rbrace() {
                    break;
                }
                let Some((directive, token)) = self.consume_word_with_token() else {
                    break;
                };
                let args = self.consume_line_args();
                match directive.as_str() {
                    "header_up" => {
                        if args.len() >= 2 {
                            request_headers.push(GatewayHeader {
                                name: args[0].clone(),
                                value: args[1..].join(" "),
                            });
                        }
                    }
                    "header_down" => {
                        if args.len() >= 2 {
                            response_headers.push(GatewayHeader {
                                name: args[0].clone(),
                                value: args[1..].join(" "),
                            });
                        }
                    }
                    "lb_policy" | "health_uri" | "health_interval" | "transport" => {}
                    _ => return Err(self.unsupported(&token, directive, "inside reverse_proxy blocks, FerroGate MVP supports header_up plus basic load-balancing and health-check declarations as typed config placeholders".to_string())),
                }
            }
        }

        self.route_count += 1;
        let prefix = inherited_prefix.unwrap_or("/");
        self.config.routes.push(GatewayRoute {
            name: format!("caddyfile-route-{}", self.route_count),
            upstream: Some(upstream_name),
            hosts: host
                .map(|value| vec![value.to_string()])
                .unwrap_or_default(),
            path_prefixes: vec![prefix.to_string()],
            strip_prefix: inherited_strip.then(|| prefix.to_string()),
            request_headers,
            response_headers,
            ..GatewayRoute::default()
        });
        Ok(())
    }
}

fn parse_first_u64(args: &[String]) -> Option<u64> {
    args.first().and_then(|value| value.parse().ok())
}
